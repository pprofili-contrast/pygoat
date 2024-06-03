
**Note: Contrast has released an Agent Operator for Kubernetes which can simplify the addition of Contrast agents into your environment, without the need for any of the steps detailed below. If that is of interest, more information can be found [here in our documentation.](https://docs.contrastsecurity.com/en/agent-operator.html)**

This guide provides a working example of _**manually**_ setting up and configuring the Contrast Python agent within a Kubernetes environment.   For the Contrast Agent Operator, see [here](https://docs.contrastsecurity.com/en/agent-operator.html).

This guide assumes you have a basic working knowledge of git, Docker and Kubernetes.

Prerequisites
-------------

1.  You will require access to a Kubernetes environment, either in the cloud (for example [Amazon's EKS](https://aws.amazon.com/eks/) or [Microsoft's AKS](https://azure.microsoft.com/en-us/products/kubernetes-service)).  Alternatively, you can set up a local Kubernetes environment.  Two options are [Docker Desktop](https://docs.docker.com/desktop/) and [minikube](https://minikube.sigs.k8s.io/docs/start/).
2.  Clone the following GitHub repository that will be used in this tutorial:
```
git clone [https://github.com/Contrast-Security-OSS/PyGoat.git](https://github.com/Contrast-Security-OSS/PyGoat.git)
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
For more details on adding the Contrast agent to your application/image. [See our docker guide on the subject](/hc/en-us/articles/360053414951 "https://support.contrastsecurity.com/hc/en-us/articles/360053414951-Python-agent-with-Docker").

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
  api\_key: <apiKey>
  service\_key: <serviceKey>
  user\_name: agent\_<hashcode>@<domain>
```
Now generate a secret using this file as follows:
```
kubectl create secret generic contrast-security --from-file=./contrast\_security.yaml
```
This secret can be used by all Contrast agents, so it is preferable to keep it generic and make any application-level configuration changes using [environment variables](https://docs.contrastsecurity.com/en/environment-variables.html).

Looking at the application deployment file (`k8s/pygoat_deployment.yaml`) you will see that this secret is already referenced and the file will be mounted under `/etc/contrast/`:
```yaml
...
        volumeMounts:
        \- name: contrast-security
          readOnly: false
          mountPath: "/etc/contrast/"
...  
      volumes:
      \- name: contrast-security
        secret:
          secretName: contrast-security
```
### Make configuration changes

Some configuration changes are required to instruct the runtime to load the Contrast Agent, and there are several configuration options that the agent allows (such as providing a custom name for the application and setting the logging level etc.).  These configuration changes can be made using [environment variables](https://docs.contrastsecurity.com/en/environment-variables.html), and a common method in Kubernetes is to create a _**ConfigMap**_.

The tutorial example already contains such a `contrast.properties` file in the `k8s` folder like so:
```
CONTRAST\_CONFIG\_PATH=/etc/contrast/contrast\_security.yaml  
CONTRAST\_\_APPLICATION\_\_NAME=pygoat-k8s  
CONTRAST\_\_SERVER\_\_NAME=AKS-Python-Pod  
CONTRAST\_\_SERVER\_\_ENVIRONMENT=qa  
CONTRAST\_\_AGENT\_\_LOGGER\_\_STDOUT=true  
CONTRAST\_\_AGENT\_\_LOGGER\_\_LEVEL=INFO
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
kubectl apply -f k8s/pygoat\_deployment.yaml
```
### Verify the agent has been loaded

Run the following command to verify the application pod is up and running:
```
kubectl get all
```
You should see something like this:
```
NAME READY STATUS RESTARTS AGE  
pod/pygoat-6f9f959d69-46dqv 1/1 Running 0 3m19s
```
And check the logs for the `pygoat` container within that pod, like so:
```
kubectl logs -c pygoat pygoat-6f9f959d69-46dqv
```
If the Contrast Agent has loaded successfully and all is working you should see output similar to the following:
```
2024-06-03 21:12:33 \[info \] Starting Contrast Agent runner pre-process  
2024-06-03 21:12:33 \[info \] Loading configuration file: /etc/contrast/contrast\_security.yaml  
2024-06-03 21:12:33 \[info \] Loading configuration file: /etc/contrast/contrast\_security.yaml  
2024-06-03 21:12:33 \[debug \] registering automatic middleware patches  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.django  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.mod\_wsgi  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.flask  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.bottle  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.pyramid.router  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.fastapi  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.aiohttp  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.falcon  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.falcon.asgi  
2024-06-03 21:12:33 \[debug \] registering middleware patches for contrast.patches.middleware.quart  
2024-06-03 21:12:34 \[info \] Loading configuration file: /etc/contrast/contrast\_security.yaml  
2024-06-03 21:12:34 \[debug \] registering automatic middleware patches  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.django  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.mod\_wsgi  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.flask  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.bottle  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.pyramid.router  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.fastapi  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.aiohttp  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.falcon  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.falcon.asgi  
2024-06-03 21:12:34 \[debug \] registering middleware patches for contrast.patches.middleware.quart  
Watching for file changes with StatReloader  
Performing system checks...  
  
System check identified no issues (0 silenced).  
June 03, 2024 - 21:12:34  
Django version 4.1.7, using settings 'pygoat.settings'  
Starting development server at http://0.0.0.0:8000/  
Quit the server with CONTROL-C.  
{"id": 140157937293776, "version": "8.4.0", "time": "2024-06-03T21:12:34.903128Z", "level": 30, "msg": "Initializing Contrast Agent contrast.agent.agent\_state", "filename": "agent\_state.py", "func\_name": "initialize", "lineno": 354, "thread": 140158013171456, "thread\_name": "django-main-thread", "pid": 7, "request\_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}  
{"time": "2024-06-03T21:12:34.924753Z", "level": 30, "msg": "Loading configuration file: /etc/contrast/contrast\_security.yaml", "filename": "configuration\_utils.py", "func\_name": "\_load\_config", "lineno": 96, "thread": 140158013171456, "thread\_name": "django-main-thread", "pid": 7, "request\_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}  
{"time": "2024-06-03T21:12:34.926622Z", "level": 30, "msg": "Contrast Agent finished loading settings.", "filename": "settings.py", "func\_name": "init", "lineno": 118, "thread": 140158013171456, "thread\_name": "django-main-thread", "pid": 7, "request\_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}  
{"api.url": "https://apptwo.contrastsecurity.com/Contrast", "api.service\_key": "\*\*REDACTED\*\*", "api.api\_key": "\*\*REDACTED\*\*", "api.user\_name": "\*\*REDACTED\*\*", "api.request\_audit.enable": "False", "api.request\_audit.path": "/app/pygoat", "api.request\_audit.requests": "False", "api.request\_audit.responses": "False", "api.certificate.enable": "False", "api.certificate.ignore\_cert\_errors": "False", "api.certificate.ca\_file": "", "api.certificate.cert\_file": "", "api.certificate.key\_file": "", "api.proxy.enable": "False", "api.proxy.url": "", "agent.logger.level": "INFO", "agent.logger.path": "contrast-agent.log", "agent.logger.stdout": "True", "agent.logger.stderr": "False", "agent.logger.progname": "Contrast Agent", "agent.security\_logger.path": "security.log", "agent.security\_logger.level": "INFO", "agent.security\_logger.syslog.enable": "False", "agent.security\_logger.syslog.protocol": "UDP", "agent.security\_logger.syslog.ip": "", "agent.security\_logger.syslog.port": "", "agent.security\_logger.syslog.facility": "19", "agent.security\_logger.syslog.severity\_exploited": "alert", "agent.security\_logger.syslog.severity\_blocked": "notice", "agent.security\_logger.syslog.severity\_blocked\_perimeter": "notice", "agent.security\_logger.syslog.severity\_probed": "warning", "agent.security\_logger.syslog.severity\_suspicious": "warning", "agent.python.enable\_sys\_monitoring": "True", "agent.python.rewrite": "True", "agent.python.policy\_rewrite": "True", "agent.python.pytest\_rewrite": "False", "agent.python.enable\_automatic\_middleware": "True", "agent.python.enable\_drf\_response\_analysis": "True", "agent.python.enable\_profiler": "False", "agent.python.profiler.enable": "False", "agent.python.tracer.enable": "False", "agent.python.assess.use\_pure\_python\_hooks": "False", "agent.polling.app\_activity\_ms": "30000", "agent.polling.server\_settings\_ms": "30000", "agent.polling.heartbeat\_ms": "30000", "application.code": "", "application.group": "", "application.metadata": "", "application.name": "pygoat-k8s", "application.path": "/", "application.tags": "", "application.version": "", "application.session\_id": "", "application.session\_metadata": "", "assess.enable": "False", "assess.enable\_scan\_response": "True", "assess.sampling.enable": "False", "assess.sampling.baseline": "5", "assess.sampling.request\_frequency": "10", "assess.sampling.window\_ms": "180000", "assess.tags": "", "assess.rules.disabled\_rules": "\[\]", "assess.stacktraces": "ALL", "assess.max\_context\_source\_events": "100", "assess.max\_propagation\_events": "1000", "assess.time\_limit\_threshold": "300000", "assess.max\_rule\_reported": "100", "assess.event\_detail": "minimal", "inventory.analyze\_libraries": "True", "inventory.enable": "True", "inventory.tags": "", "protect.enable": "False", "protect.samples.probed": "50", "protect.samples.blocked": "25", "protect.samples.exploited": "100", "protect.samples.blocked\_at\_perimeter": "25", "protect.rules.bot-blocker.enable": "False", "protect.rules.cmd-injection.mode": "OFF", "protect.rules.disabled\_rules": "\[\]", "protect.rules.method-tampering.mode": "OFF", "protect.rules.nosql-injection.mode": "OFF", "protect.rules.path-traversal.mode": "OFF", "protect.rules.reflected-xss.mode": "OFF", "protect.rules.sql-injection.mode": "OFF", "protect.rules.ssrf.mode": "OFF", "protect.rules.unsafe-file-upload.mode": "OFF", "protect.rules.untrusted-deserialization.mode": "OFF", "protect.rules.xxe.mode": "OFF", "enable": "True", "server.name": "AKS-Python-Pod", "server.path": "/", "server.type": "", "server.version": "", "server.environment": "qa", "server.tags": "", "time": "2024-06-03T21:12:34.926915Z", "level": 30, "msg": "Current Configuration", "filename": "agent\_config.py", "func\_name": "log\_config", "lineno": 94, "thread": 140158013171456, "thread\_name": "django-main-thread", "pid": 7, "request\_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}  
{"python\_version": "3.11.0b1 (main, May 28 2022, 12:48:33) \[GCC 8.3.0\]", "agent\_version": "8.4.0", "assess\_enabled": true, "protect\_enabled": true, "using\_runner": true, "using\_rewriter": true, "has\_funchook": false, "using\_sys\_monitoring": false, "log\_level": "INFO", "configured\_application\_name": "pygoat-k8s", "detected\_application\_name": "pygoat", "detected\_framework": "django", "installed\_framework": "Django 4.1.7", "installed\_webserver": "Unknown 0.0.0", "cwd": "/app/pygoat", "executable": "/usr/local/bin/python", "platform": "Linux-5.15.0-1057-azure-x86\_64-with-glibc2.28", "default\_encoding": "UTF-8", "time": "2024-06-03T21:12:35.479051Z", "level": 30, "msg": "ENVIRONMENT", "filename": "agent\_state.py", "func\_name": "\_log\_environment", "lineno": 121, "thread": 140158013171456, "thread\_name": "django-main-thread", "pid": 7, "request\_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}  
{"id": 140157937293776, "time": "2024-06-03T21:12:35.479321Z", "level": 30, "msg": "Finished Initializing Contrast Agent contrast.agent.agent\_state", "filename": "agent\_state.py", "func\_name": "initialize", "lineno": 436, "thread": 140158013171456, "thread\_name": "django-main-thread", "pid": 7, "request\_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}  
The Contrast Python Agent collects usage data in order to help us improve compatibility and security coverage. The data is anonymous and does not contain application data. It is collected by Contrast and is never shared. You can opt-out of telemetry by setting the CONTRAST\_AGENT\_TELEMETRY\_OPTOUT environment variable to '1' or 'true'. Read more about Contrast Python Agent telemetry: https://docs.contrastsecurity.com/en/python-telemetry.html  
{"time": "2024-06-03T21:12:35.556091Z", "level": 30, "msg": "The Contrast Python Agent collects usage data in order to help us improve compatibility and security coverage. The data is anonymous and does not contain application data. It is collected by Contrast and is never shared. You can opt-out of telemetry by setting the CONTRAST\_AGENT\_TELEMETRY\_OPTOUT environment variable to '1' or 'true'. Read more about Contrast Python Agent telemetry: https://docs.contrastsecurity.com/en/python-telemetry.html", "filename": "telemetry.py", "func\_name": "\_find\_or\_create\_file", "lineno": 344, "thread": 140157878994688, "thread\_name": "ContrastTelemetry", "pid": 7, "request\_id": null, "hostname": "pygoat-6f9f959d69-46dqv", "name": "Contrast Agent", "v": 0}
```
