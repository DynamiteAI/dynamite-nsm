# dynamite_nsm.utilities

## check_pid
```python
check_pid(pid)
```

Check For the existence of a unix pid.

- *return* True, if the process is running

## check_socket
```python
check_socket(host, port)
```

Check if a host is listening on a given port

- *param* host: The host the service is listening on
- *param* port: The port the service is listening on
- *return* True, if a service is listening on a given HOST:PORT

## create_dynamite_user
```python
create_dynamite_user(password)
```

Create the dynamite user

- *param* password: The password for the user

## download_file
```python
download_file(url, filename, stdout=False)
```

Given a URL and destination file name, download the file to local install_cache

- *param* url: The url to the file to download
- *param* filename: The name of the file to store
- *return* None

## generate_random_password
```python
generate_random_password(length=30)
```

Generate a random password containing alphanumeric and symbolic characters
- *param* length: The length of the password
- *return* The string representation of the password

## get_environment_file_str
```python
get_environment_file_str()
```

- *return* The contents of the /etc/dynamite/environment file as a giant export string

## get_environment_file_dict
```python
get_environment_file_dict()
```

- *return* The contents of the /etc/dynamite/environment file as a dictionary

## get_memory_available_bytes
```python
get_memory_available_bytes()
```

Get the amount of RAM (in bytes) of the current system

- *return* The number of bytes available in memory

## get_network_interface_names
```python
get_network_interface_names()
```

Returns a list of network interfaces available on the system

- *return* A list of network interfaces

## get_cpu_core_count
```python
get_cpu_core_count()
```

- *return* The count of CPU cores available on the system

## is_root
```python
is_root()
```

Determine whether or not the current user is root

- *return* True, if the user is root

## prompt_input
```python
prompt_input(message)
```

Compatibility function for Python2/3 for taking in input

- *param* message: The message appearing next to the input prompt.
return: The inputted text

## prompt_password
```python
prompt_password(prompt='Enter a secure password: ', confirm_prompt='Confirm Password: ')
```

Prompt user for password, and confirm

- *param* prompt: The first password prompt
- *param* confirm_prompt: The confirmation prompt
- *return* The password entered

## setup_java
```python
setup_java()
```

Installs the latest version of OpenJDK

## set_ownership_of_file
```python
set_ownership_of_file(path)
```

Set the ownership of a file to dynamite user/group at a given path

- *param* path: The path to the file

## set_permissions_of_file
```python
set_permissions_of_file(file_path, unix_permissions_integer)
```

Set the permissions of a file to unix_permissions_integer

- *param* file_path: The path to the file
- *param* unix_permissions_integer: The numeric representation of user/group/everyone permissions on a file

## update_sysctl
```python
update_sysctl()
```

Updates the vm.max_map_count and fs.file-max count

## tail_file
```python
tail_file(path, n=1, bs=1024)
```

Tail the last n lines of a file at a given path

- *param* path: The path to the file
- *param* n: The last n number of lines
- *param* bs: The block-size in bytes
- *return* A list of lines

## update_user_file_handle_limits
```python
update_user_file_handle_limits()
```

Updates the max number of file handles the dynamite user can have open

