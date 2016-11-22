# ActiveRecord/RubyCAS Extauth script for Ejabberd

### Installation & usage
Install gems dependencies:
```sh
$ bundle install --without sqlite postgres --system
```
Configure ejabberd:
```
host_config:
  "example.com":
     auth_method: external
     extauth_program: "/path/extauth.rb /path/config.yml"
```
