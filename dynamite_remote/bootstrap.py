import os
from dynamite_remote import utilities

user_home = os.environ.get('HOME')


def create_ssh_wrapper_script():
    ssh_wrapper_script = '''
#! /bin/bash

DYNAMITE_REMOTE_LOCKS=$HOME/.dynamite_remote/locks/

# Create the locks directory if it does not exist
mkdir -p $DYNAMITE_REMOTE_LOCKS
ssh_command=$(which ssh)

# Parse the commandline arguments passed in by node.py
array=( $@ )
len=${#array[@]}
hostname_or_ip=$(awk -F@ '{print $2}' <<< "${array[@]:0:1}")
node_command="${array[@]:8:$len-1}"


# Create a lock file
# echo Creating lock. $DYNAMITE_REMOTE_LOCKS/$hostname_or_ip
touch "$DYNAMITE_REMOTE_LOCKS/$hostname_or_ip"
echo "$node_command" > "$DYNAMITE_REMOTE_LOCKS/$hostname_or_ip"
$ssh_command "$@"

# Remove the lock
# echo Removing lock. $DYNAMITE_REMOTE_LOCKS/$hostname_or_ip
rm $DYNAMITE_REMOTE_LOCKS/$hostname_or_ip
'''

    wrapper_directory = f'{user_home}/.dynamite_remote/bin/'
    utilities.makedirs(wrapper_directory)
    with open(f'{wrapper_directory}/ssh_wrapper.sh', 'w') as ssh_wrapper_out:
        ssh_wrapper_out.write(ssh_wrapper_script)
        utilities.set_permissions_of_file(f'{wrapper_directory}/ssh_wrapper.sh', '+x')