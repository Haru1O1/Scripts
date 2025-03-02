# Ansible scripts

There are three scripts netstat_script.yml, user_script.yml, setup_mysql.yml

Netstat_script
- Install dependecies: net-tools
- Check for active TCP and UDP connections
- List of currently active ports and by what processes

User_script
- List currently logged on users
- List of all users created
- List of the creation date and the user(with a home directory) associated with it

Setup_mysql
- Prompt for a name for a database
- Prompt for a username for a mysql user
- Prompt for a password for the mysql user
- Installs dependecies: default-mysql-server and python3-mysqldb
- Starts MySQL service
- Set MySQL root password with default password 'R00/My5ql01'
- Create a database with the name given
- Check if a mysql user with the username exists
- Attempts to login in if the user exists already
- Creates a user with the username and password if it does not exist
