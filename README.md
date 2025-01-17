# certificate-manager
Certificate controller will handle TLS self signed certificate is generated or updated to referenced secret.

## Description
It will help developers on our Kubernetes clusters to request TLS certificates that they
can incorporate into their application deployments

## Getting Started

### Prerequisites
- go version v1.22.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.


**Install the CRDs into the cluster:**

```sh
make install
```

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -f config/samples/certificate.yaml
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -f config/samples/certificate.yaml
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**Run test:**

```sh
make test
```

**Run controller:**

```sh
make run
```

**Build controller and Run:**

```sh
make build
./bin/manager
```

## License

Copyright 2024 krishna.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

