#What is drydock?
**drydock** is a Docker security audit tool written in Python. It was initially inspired by [docker-bench-security](https://github.com/docker/docker-bench-security) but aims to provide a more flexible way for assesing Docker installations and deployments. drydock allows easy creation and use of **custom audit profiles** in order to eliminate noise and false alarms. Reports are saved in JSON format for easier parsing. 

At the moment all of the security checks performed are based on the [CIS Docker 1.6 Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.6_Benchmark_v1.0.0.pdf). 


## Usage
Using drydock is as simple as :

```sh
git clone https://github.com/zuBux/drydock.git
pip install -r requirements.txt
python drydock.py
```
drydock makes heavy use of [docker-py](https://github.com/docker/docker-py) client API to communicate with Docker. Protocol, host and port number can be changed through the BASE_URL variable located in audits/audit.py (default value is 'unix://var/run/docker.sock')

The following options are available: 

* -o <file_name> : Specifies the path where JSON output will be saved. Switches to output.json if none specified.

* -p <profile> : The profile which will be used for the audit. Switches to conf/default.yaml if none specified.


A profile containing all checks is provided in conf/default.yaml and can be used as reference for creating custom profiles. You can disable an audit by commenting it out (and its options, if any).

**Users are advised to run drydock as root** for more accurate results.


## TODO


- Web Interface - Frontend in Flask(or Bottle) and Jinja2 for profile creation, importing results etc.
- Database support - Keeping track of results, provide analytics etc.
- Remote host support (?)


## Contributions

drydock is in alpha stage and needs testing under different environments (currently tested only on Ubuntu/Debian deployments). All contributions ( bugs/improvements/suggestions etc. ) are welcome!
