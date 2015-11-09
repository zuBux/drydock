#What is drydock?
**drydock** is a Docker security audit tool written in Python. It was initially inspired by [docker-bench-security](https://github.com/docker/docker-bench-security) but aims to provide a more flexible way for assesing Docker installations and deployments. drydock allows easy creation and use of **custom audit profiles** in order to eliminate noise and false alarms. Reports are saved in JSON format for easier parsing. drydock makes heavy use of [docker-py](https://github.com/docker/docker-py) client API to communicate with Docker.

At the moment all of the security checks performed are based on the [CIS Docker 1.6 Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.6_Benchmark_v1.0.0.pdf). 

## Usage
Using drydock is as simple as :

```sh
git clone https://github.com/zuBux/drydock.git
pip install -r requirements.txt
python drydock.py
```
A profile containing all checks is provided in conf/default.yaml and can be used as reference for creating custom profiles. You can disable an audit by commenting it out (and its options, if any).

Since there are audits which require administrative privileges (e.x examining auditd rules) **users are advised to run drydock as root** for more accurate results.

### Local Docker host
Assuming that your Docker daemon uses unix sockets (default configuration), the following options are available:

* -o <file_name> : Specifies the path where JSON output will be saved. Switches to output.json if none specified.
* -p <path to profile> : The profile which will be used for the audit. Switches to conf/default.yaml if none specified.
* -v <verbosity> : Use values 1, 2 or 3 to change verbosity level to ERROR, WARNING or DEBUG accordingly. Default is 1

### Remote Docker host
If your Docker daemon listens on an exposed port, using TLS, you must provide the following :

* -d <IP:port> Docker daemon IP and listening port
* -c <path> Client certificate
* -k <path> Client certificate key

## TODO
- Web Interface - Frontend in Flask(or Bottle) and Jinja2 for profile creation, importing results etc.
- Database support - Keeping track of results, provide analytics etc.

## Contributions
drydock is in beta stage and **needs testing under different environments** (currently tested only on Ubuntu/Debian deployments). All contributions ( bugs/improvements/suggestions etc. ) are welcome!
