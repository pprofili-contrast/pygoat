
**Note: Contrast has released an Agent Operator for Kubernetes which can simplify the addition of Contrast agents into your environment, without the need for any of the steps detailed below. If that is of interest, more information can be found [here in our documentation.](https://docs.contrastsecurity.com/en/agent-operator.html)**
---
This guide provides a working example of _**manually**_ setting up and configuring the Contrast Python agent within a Kubernetes environment.   For the Contrast Agent Operator, see [here](https://docs.contrastsecurity.com/en/agent-operator.html).

This guide assumes you have a basic working knowledge of git, Docker and Kubernetes.

Prerequisites
-------------

1.  You will require access to a Kubernetes environment, either in the cloud (for example [Amazon's EKS](https://aws.amazon.com/eks/) or [Microsoft's AKS](https://azure.microsoft.com/en-us/products/kubernetes-service)).  Alternatively, you can set up a local Kubernetes environment.  Two options are [Docker Desktop](https://docs.docker.com/desktop/) and [minikube](https://minikube.sigs.k8s.io/docs/start/).
2.  Clone the following GitHub repository that will be used in this tutorial:
```
git clone https://github.com/Contrast-Security-OSS/PyGoat.git
```
Building the Python application's image with Contrast
-----------------------------------------------------

Inspect the `Dockerfile.contrast`, you should note a few sections where the Contrast agent is added:

Line 16 installs the latest Python agent from PyPI:
```
# Install the Contrast agent  
RUN pip install -U contrast-agent
```
And line 32 modifies the CMD instruction for the container to add the Contrast Runner which invokes the agent.
```
CMD ["contrast-python-run","--","/usr/local/bin/python","/app/manage.py","runserver","0.0.0.0:8000"]
```
For more details on adding the Contrast agent to your application/image. [See our docker guide on the subject](https://support.contrastsecurity.com/hc/en-us/articles/360053414951-Python-agent-with-Docker).

1.  In your terminal, navigate to the cloned repo's folder and run the following command to build the docker image with a tag that references your docker repository.
```
docker build -f Dockerfile.contrast . -t <your repo>/pygoat:contrast
```
2.  Push your image to the repo.
```
docker push <your repo>/pygoat:contrast
```
This image can be now be used in the Kubernetes deployment below.

Setting up the Kubernetes environment
-------------------------------------

### Create a secret for the agent's authentication credentials

[Download](https://docs.contrastsecurity.com/en/configuration-settings.html#:~:text=Environment%20variables.-,YAML%20configuration%20file,-.) a `contrast_security.yaml` file from the Contrast UI to acquire the agent authentication credentials which will be used to create a secret in Kubernetes.  The file will look like this:
```yaml
api: 
  url: http(s)://<your contrast UI hostname>/Contrast #For example https://app.contrastsecurity.com/Contrast
  api_key: <apiKey>
  service_key: <serviceKey>
  user_name: agent_<hashcode>@<domain>
```
Now generate a secret using this file as follows:
```
kubectl create secret generic contrast-security --from-file=./contrast_security.yaml
```
This secret can be used by all Contrast agents, so it is preferable to keep it generic and make any application-level configuration changes using [environment variables](https://docs.contrastsecurity.com/en/environment-variables.html).

Looking at the application deployment file (`k8s/pygoat_deployment.yaml`) you will see that this secret is already referenced and the file will be mounted under `/etc/contrast/`:
```yaml
...
        volumeMounts:
        - name: contrast-security
          readOnly: false
          mountPath: "/etc/contrast/"
...  
      volumes:
      - name: contrast-security
        secret:
          secretName: contrast-security
```
### Make configuration changes

Some configuration changes are required to instruct the runtime to load the Contrast Agent, and there are several configuration options that the agent allows (such as providing a custom name for the application and setting the logging level etc.).  These configuration changes can be made using [environment variables](https://docs.contrastsecurity.com/en/environment-variables.html), and a common method in Kubernetes is to create a _**ConfigMap**_.

The tutorial example already contains such a `contrast.properties` file in the `k8s` folder like so:
```
CONTRAST_CONFIG_PATH=/etc/contrast/contrast_security.yaml  
CONTRAST__APPLICATION__NAME=pygoat-k8s  
CONTRAST__SERVER__NAME=AKS-Python-Pod  
CONTRAST__SERVER__ENVIRONMENT=qa  
CONTRAST__AGENT__LOGGER__STDOUT=true  
CONTRAST__AGENT__LOGGER__LEVEL=INFO
```
You can customize this as desired and then create the ConfigMap from this file, run the following command:

kubectl create configmap contrast-config --from-env-file=k8s/contrast.properties

And you will notice that, again, the application deployment file (`k8s/pygoat_deployment.yaml`) already references this ConfigMap:
```yaml
...  
   envFrom:  
   - configMapRef:  
       name: contrast-config  
...
```
### Reference your Docker Image

The application deployment file (`k8s/pygoat_deployment.yaml`) is currently configured to reference a pre-built image named `pprofili/pygoat:k8s`.  To instead have the deployment use the Docker image you built [above](#building-and-setting-up-the-net-core-applications-image-wcontrast), modify this line to point to your own Docker repository, for example change this:
```yaml
 - name: pygoat  
   image: pprofili/pygoat:k8s
```
to this:
```yaml
 - name: pygoat  
   image: <your repo>/pygoat:contrast
```
### Deploy the application to Kubernetes

Apply the deployment file using the following command
```
kubectl apply -f k8s/pygoat_deployment.yaml
```
### Verify the agent has been loaded

Run the following command to verify the application pod is up and running:
```
kubectl get all
```
You should see something like this:
```
NAME                        READY STATUS  RESTARTS AGE  
pod/pygoat-6f9f959d69-46dqv 1/1   Running 0        3m19s
```
And check the logs for the `pygoat` container within that pod, like so:
```
kubectl logs -c pygoat pygoat-6f9f959d69-46dqv
```
If the Contrast Agent has loaded successfully and all is working you should see output similar to the following:
```
2024-06-03 21:12:33 [info     ] Starting Contrast Agent runner pre-process
2024-06-03 21:12:33 [info     ] Loading configuration file: /etc/contrast/contrast_security.yaml
2024-06-03 21:12:33 [info     ] Loading configuration file: /etc/contrast/contrast_security.yaml
2024-06-03 21:12:33 [debug    ] registering automatic middleware patches
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.django
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.mod_wsgi
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.flask
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.bottle
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.pyramid.router
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.fastapi
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.aiohttp
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.falcon
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.falcon.asgi
2024-06-03 21:12:33 [debug    ] registering middleware patches for contrast.patches.middleware.quart
2024-06-03 21:12:34 [info     ] Loading configuration file: /etc/contrast/contrast_security.yaml
2024-06-03 21:12:34 [debug    ] registering automatic middleware patches
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.django
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.mod_wsgi
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.flask
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.bottle
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.pyramid.router
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.fastapi
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.aiohttp
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.falcon
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.falcon.asgi
2024-06-03 21:12:34 [debug    ] registering middleware patches for contrast.patches.middleware.quart
Watching for file changes with StatReloader
Performing system checks...

System check identified no issues (0 silenced).
June 03, 2024 - 21:12:34
Django version 4.1.7, using settings 'pygoat.settings'
Starting development server at http://0.0.0.0:8000/
Quit the server with CONTROL-C.
{"id": 140157937293776, "version": "8.4.0", "time": "2024-06-03T21:12:34.903128Z", "level": 30, "msg": "Initializing Contrast Agent contrast.agent.agent_state", "filename": "agent_state.py", "func_name": "initialize", "lineno": 354, "thread": 140158013171456, "thread_name": "django-main-thread", "pid": 7, "request_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}
{"time": "2024-06-03T21:12:34.924753Z", "level": 30, "msg": "Loading configuration file: /etc/contrast/contrast_security.yaml", "filename": "configuration_utils.py", "func_name": "_load_config", "lineno": 96, "thread": 140158013171456, "thread_name": "django-main-thread", "pid": 7, "request_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}
{"time": "2024-06-03T21:12:34.926622Z", "level": 30, "msg": "Contrast Agent finished loading settings.", "filename": "settings.py", "func_name": "init", "lineno": 118, "thread": 140158013171456, "thread_name": "django-main-thread", "pid": 7, "request_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}
{"api.url": "https://apptwo.contrastsecurity.com/Contrast", "api.service_key": "**REDACTED**", "api.api_key": "**REDACTED**", "api.user_name": "**REDACTED**", "api.request_audit.enable": "False", "api.request_audit.path": "/app/pygoat", "api.request_audit.requests": "False", "api.request_audit.responses": "False", "api.certificate.enable": "False", "api.certificate.ignore_cert_errors": "False", "api.certificate.ca_file": "", "api.certificate.cert_file": "", "api.certificate.key_file": "", "api.proxy.enable": "False", "api.proxy.url": "", "agent.logger.level": "INFO", "agent.logger.path": "contrast-agent.log", "agent.logger.stdout": "True", "agent.logger.stderr": "False", "agent.logger.progname": "Contrast Agent", "agent.security_logger.path": "security.log", "agent.security_logger.level": "INFO", "agent.security_logger.syslog.enable": "False", "agent.security_logger.syslog.protocol": "UDP", "agent.security_logger.syslog.ip": "", "agent.security_logger.syslog.port": "", "agent.security_logger.syslog.facility": "19", "agent.security_logger.syslog.severity_exploited": "alert", "agent.security_logger.syslog.severity_blocked": "notice", "agent.security_logger.syslog.severity_blocked_perimeter": "notice", "agent.security_logger.syslog.severity_probed": "warning", "agent.security_logger.syslog.severity_suspicious": "warning", "agent.python.enable_sys_monitoring": "True", "agent.python.rewrite": "True", "agent.python.policy_rewrite": "True", "agent.python.pytest_rewrite": "False", "agent.python.enable_automatic_middleware": "True", "agent.python.enable_drf_response_analysis": "True", "agent.python.enable_profiler": "False", "agent.python.profiler.enable": "False", "agent.python.tracer.enable": "False", "agent.python.assess.use_pure_python_hooks": "False", "agent.polling.app_activity_ms": "30000", "agent.polling.server_settings_ms": "30000", "agent.polling.heartbeat_ms": "30000", "application.code": "", "application.group": "", "application.metadata": "", "application.name": "pygoat-k8s", "application.path": "/", "application.tags": "", "application.version": "", "application.session_id": "", "application.session_metadata": "", "assess.enable": "False", "assess.enable_scan_response": "True", "assess.sampling.enable": "False", "assess.sampling.baseline": "5", "assess.sampling.request_frequency": "10", "assess.sampling.window_ms": "180000", "assess.tags": "", "assess.rules.disabled_rules": "[]", "assess.stacktraces": "ALL", "assess.max_context_source_events": "100", "assess.max_propagation_events": "1000", "assess.time_limit_threshold": "300000", "assess.max_rule_reported": "100", "assess.event_detail": "minimal", "inventory.analyze_libraries": "True", "inventory.enable": "True", "inventory.tags": "", "protect.enable": "False", "protect.samples.probed": "50", "protect.samples.blocked": "25", "protect.samples.exploited": "100", "protect.samples.blocked_at_perimeter": "25", "protect.rules.bot-blocker.enable": "False", "protect.rules.cmd-injection.mode": "OFF", "protect.rules.disabled_rules": "[]", "protect.rules.method-tampering.mode": "OFF", "protect.rules.nosql-injection.mode": "OFF", "protect.rules.path-traversal.mode": "OFF", "protect.rules.reflected-xss.mode": "OFF", "protect.rules.sql-injection.mode": "OFF", "protect.rules.ssrf.mode": "OFF", "protect.rules.unsafe-file-upload.mode": "OFF", "protect.rules.untrusted-deserialization.mode": "OFF", "protect.rules.xxe.mode": "OFF", "enable": "True", "server.name": "AKS-Python-Pod", "server.path": "/", "server.type": "", "server.version": "", "server.environment": "qa", "server.tags": "", "time": "2024-06-03T21:12:34.926915Z", "level": 30, "msg": "Current Configuration", "filename": "agent_config.py", "func_name": "log_config", "lineno": 94, "thread": 140158013171456, "thread_name": "django-main-thread", "pid": 7, "request_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}
{"python_version": "3.11.0b1 (main, May 28 2022, 12:48:33) [GCC 8.3.0]", "agent_version": "8.4.0", "assess_enabled": true, "protect_enabled": true, "using_runner": true, "using_rewriter": true, "has_funchook": false, "using_sys_monitoring": false, "log_level": "INFO", "configured_application_name": "pygoat-k8s", "detected_application_name": "pygoat", "detected_framework": "django", "installed_framework": "Django 4.1.7", "installed_webserver": "Unknown 0.0.0", "cwd": "/app/pygoat", "executable": "/usr/local/bin/python", "platform": "Linux-5.15.0-1057-azure-x86_64-with-glibc2.28", "default_encoding": "UTF-8", "time": "2024-06-03T21:12:35.479051Z", "level": 30, "msg": "ENVIRONMENT", "filename": "agent_state.py", "func_name": "_log_environment", "lineno": 121, "thread": 140158013171456, "thread_name": "django-main-thread", "pid": 7, "request_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}
{"id": 140157937293776, "time": "2024-06-03T21:12:35.479321Z", "level": 30, "msg": "Finished Initializing Contrast Agent contrast.agent.agent_state", "filename": "agent_state.py", "func_name": "initialize", "lineno": 436, "thread": 140158013171456, "thread_name": "django-main-thread", "pid": 7, "request_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}
The Contrast Python Agent collects usage data in order to help us improve compatibility and security coverage. The data is anonymous and does not contain application data. It is collected by Contrast and is never shared. You can opt-out of telemetry by setting the CONTRAST_AGENT_TELEMETRY_OPTOUT environment variable to '1' or 'true'. Read more about Contrast Python Agent telemetry: https://docs.contrastsecurity.com/en/python-telemetry.html
{"time": "2024-06-03T21:12:35.556091Z", "level": 30, "msg": "The Contrast Python Agent collects usage data in order to help us improve compatibility and security coverage. The data is anonymous and does not contain application data. It is collected by Contrast and is never shared. You can opt-out of telemetry by setting the CONTRAST_AGENT_TELEMETRY_OPTOUT environment variable to '1' or 'true'. Read more about Contrast Python Agent telemetry: https://docs.contrastsecurity.com/en/python-telemetry.html", "filename": "telemetry.py", "func_name": "_find_or_create_file", "lineno": 344, "thread": 140157878994688, "thread_name": "ContrastTelemetry", "pid": 7, "request_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}
```
