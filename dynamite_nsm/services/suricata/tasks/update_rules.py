import io
import os
import re
import shutil
import subprocess
from typing import Optional
from datetime import datetime

from suricata.update import net
from suricata.update import util
from suricata.update import config
from suricata.update import engine

from dynamite_nsm import utilities
from dynamite_nsm import exceptions
from dynamite_nsm.services.base import tasks
from dynamite_nsm.services.suricata.rules.objects import RuleFile


class DummyArgs:
    config = None
    offline = False
    force = False
    quiet = True
    url = []
    now = datetime.now()


class UpdateRules(tasks.BaseTask):

    def __init__(self, no_merge: Optional[bool] = False, sid_msg_map_file: Optional[str] = None,
                 sid_msg_map_2_file: Optional[str] = None, threshold_in_file: Optional[str] = None,
                 threshold_out_file: Optional[str] = None,
                 yaml_fragment_file: Optional[str] = None, force: Optional[bool] = False,
                 verbose: Optional[bool] = False, stdout: Optional[bool] = True):

        env = utilities.get_environment_file_dict()
        self.configuration_directory = env.get('SURICATA_CONFIG')
        self.install_directory = env.get('SURICATA_HOME')
        self.no_merge = no_merge
        self.threshold_in_file = threshold_in_file
        self.threshold_out_file = threshold_out_file
        self.sid_msg_map_file = sid_msg_map_file
        self.sid_msg_map_2_file = sid_msg_map_2_file
        self.force = force
        self.yaml_fragment_file = yaml_fragment_file
        config.DEFAULT_DATA_DIRECTORY = f'{self.configuration_directory}/data/'
        config.DEFAULT_UPDATE_YAML_PATH = f'{self.configuration_directory}/update.yaml'
        config.DEFAULT_SURICATA_YAML_PATH = [f'{self.configuration_directory}/suricata.yaml']
        self.config = config
        super().__init__('update_suricata_rules', verbose=verbose, stdout=stdout)

    def invoke(self):
        from suricata.update import main
        from suricata.update.main import FileTracker, ThresholdProcessor
        from suricata.update.main import DEFAULT_OUTPUT_RULE_FILENAME

        from suricata.update.main import build_rule_map, check_vars, check_output_directory, copytree, \
            copytree_ignore_backup, disable_ja3, ignore_file, load_matchers, load_filters, load_drop_filters, \
            load_sources, load_dist_rules, matchers_mod, manage_classification, notes, rule_mod, resolve_flowbits, \
            test_suricata, write_merged, write_yaml_fragment, write_sid_msg_map, write_to_directory

        main.args = DummyArgs()
        config.init(DummyArgs())
        self.logger.info('Beginning Suricata Rule Update')
        suricata_path = f'{self.install_directory}/bin/suricata'
        suricata_conf_path = f'{self.configuration_directory}/suricata.yaml'
        suricata_version = engine.get_version(suricata_path)
        net.set_user_agent_suricata_version(suricata_version.full)
        file_tracker = FileTracker()

        disable_matchers = []
        enable_matchers = []
        modify_filters = []
        drop_filters = []

        # Load user provided disable filters.
        disable_conf_filename = config.get("disable-conf")
        if disable_conf_filename and os.path.exists(disable_conf_filename):
            self.logger.info(f"Loading {disable_conf_filename}.")
            disable_matchers += load_matchers(disable_conf_filename)

        # Load user provided enable filters.
        enable_conf_filename = config.get("enable-conf")
        if enable_conf_filename and os.path.exists(enable_conf_filename):
            self.logger.info(f"Loading {enable_conf_filename}.")
            enable_matchers += load_matchers(enable_conf_filename)

        # Load user provided modify filters.
        modify_conf_filename = config.get("modify-conf")
        if modify_conf_filename and os.path.exists(modify_conf_filename):
            modify_filters += load_filters(modify_conf_filename)

        # Load user provided drop filters.
        drop_conf_filename = config.get("drop-conf")
        if drop_conf_filename and os.path.exists(drop_conf_filename):
            drop_filters += load_drop_filters(drop_conf_filename)

        # Load the Suricata configuration if we can.
        suriconf = None

        if suricata_conf_path and \
                os.path.exists(suricata_conf_path) and \
                suricata_path and os.path.exists(suricata_path):
            try:
                suriconf = engine.Configuration.load(
                    suricata_conf_path, suricata_path=suricata_path)
            except subprocess.CalledProcessError:
                return exceptions.CallProcessError(f'Could not invoke {suricata_path}')
        # Disable rule that are for app-layers that are not enabled.
        if suriconf:
            for key in suriconf.keys():
                m = re.match("app-layer\.protocols\.([^\.]+)\.enabled", key)
                if m:
                    proto = m.group(1)
                    if not suriconf.is_true(key, ["detection-only"]):
                        disable_matchers.append(matchers_mod.ProtoRuleMatcher(proto))
                    elif proto == "smb" and suriconf.build_info:
                        # Special case for SMB rules. For versions less
                        # than 5, disable smb rules if Rust is not
                        # available.
                        if suriconf.build_info["version"].major < 5:
                            if not "RUST" in suriconf.build_info["features"]:
                                disable_matchers.append(matchers_mod.ProtoRuleMatcher(proto))
            # Check that the cache directory exists and is writable.
            if not os.path.exists(config.get_cache_dir()):
                try:
                    os.makedirs(config.get_cache_dir(), mode=0o770)
                except Exception:
                    config.set_cache_dir("/var/tmp")

            files = load_sources(suricata_version)

            load_dist_rules(files)

            rules = []
            classification_files = []
            dep_files = {}
            for entry in sorted(files, key=lambda e: e.filename):
                if "classification.config" in entry.filename:
                    classification_files.append((entry.filename, entry.content))
                    continue
                if not entry.filename.endswith(".rules"):
                    dep_files.update({entry.filename: entry.content})
                    continue
                if ignore_file(config.get("ignore"), entry.filename):
                    continue
                rules += rule_mod.parse_fileobj(io.BytesIO(entry.content), entry.filename)

            rulemap = build_rule_map(rules)

            # Counts of user enabled and modified rules.
            enable_count = 0
            modify_count = 0
            drop_count = 0

            # List of rules disabled by user. Used for counting, and to log
            # rules that are re-enabled to meet flowbit requirements.
            disabled_rules = []
            for key, rule in rulemap.items():

                # To avoid duplicate counts when a rule has more than one modification
                # to it, we track the actions here then update the counts at the end.
                enabled = False
                modified = False
                dropped = False

                for matcher in disable_matchers:
                    if rule.enabled and matcher.match(rule):
                        rule.enabled = False
                        disabled_rules.append(rule)

                for matcher in enable_matchers:
                    if not rule.enabled and matcher.match(rule):
                        rule.enabled = True
                        enabled = True

                for fltr in drop_filters:
                    if fltr.match(rule):
                        rule = fltr.run(rule)
                        dropped = True

                for fltr in modify_filters:
                    if fltr.match(rule):
                        rule = fltr.run(rule)
                        modified = True

                if enabled:
                    enable_count += 1
                if modified:
                    modify_count += 1
                if dropped:
                    drop_count += 1

                rulemap[key] = rule

            # Check if we should disable ja3 rules.
            try:
                disable_ja3(suriconf, rulemap, disabled_rules)
            except Exception as err:
                self.logger.error("Failed to dynamically disable ja3 rules: %s" % (err))

            # Check rule vars, disabling rules that use unknown vars.
            check_vars(suriconf, rulemap)

            self.logger.info("Disabled %d rules." % (len(disabled_rules)))
            self.logger.info("Enabled %d rules." % (enable_count))
            self.logger.info("Modified %d rules." % (modify_count))
            self.logger.info("Dropped %d rules." % (drop_count))

            # Fixup flowbits.
            resolve_flowbits(rulemap, disabled_rules)

            # Check that output directory exists, creating it if needed.
            check_output_directory(config.get_output_dir())

            # Check that output directory is writable.
            if not os.access(config.get_output_dir(), os.W_OK):
                self.logger.error(f"Output directory is not writable: {config.get_output_dir()}")
                raise PermissionError(config.get_output_dir())

            # Backup the output directory.
            self.logger.info("Backing up current rules.")
            backup_directory = util.mktempdir()
            shutil.copytree(config.get_output_dir(), os.path.join(
                backup_directory, "backup"), ignore=copytree_ignore_backup)

            if not self.no_merge:
                # The default, write out a merged file.
                output_filename = os.path.join(
                    config.get_output_dir(), DEFAULT_OUTPUT_RULE_FILENAME)
                file_tracker.add(output_filename)
                write_merged(os.path.join(output_filename), rulemap, dep_files)
            else:
                for file in files:
                    file_tracker.add(
                        os.path.join(
                            config.get_output_dir(), os.path.basename(file.filename)))
                write_to_directory(config.get_output_dir(), files, rulemap, dep_files)

            manage_classification(suriconf, classification_files)

            if self.yaml_fragment_file:
                file_tracker.add(self.yaml_fragment_file)
                write_yaml_fragment(self.yaml_fragment_file, files)

            if self.sid_msg_map_file:
                write_sid_msg_map(self.sid_msg_map_file, rulemap, version=1)
            if self.sid_msg_map_2_file:
                write_sid_msg_map(self.sid_msg_map_2_file, rulemap, version=2)

            if self.threshold_in_file and self.threshold_out_file:
                file_tracker.add(self.threshold_out_file)
                threshold_processor = ThresholdProcessor()
                threshold_processor.process(
                    open(self.threshold_in_file), open(self.threshold_out_file, "w"), rulemap)

            self.logger.info('Merging in changes.')
            rule_file = RuleFile(f'{self.configuration_directory}/data/rules/suricata.rules')
            rule_file.build_cache()
            rule_file.merge()
            rule_file.commit()

            if not test_suricata(suricata_path):
                self.logger.error("Suricata test failed, aborting.")
                self.logger.error("Restoring previous rules.")
                copytree(
                    os.path.join(backup_directory, "backup"), config.get_output_dir())


if __name__ == '__main__':
    UpdateRules().invoke()
