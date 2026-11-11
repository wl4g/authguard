"""Phase 00: deploy and validate the complete real E2E topology."""
from __future__ import annotations
import yaml
import time
import re
import os
import json
import hashlib
import base64
from util.postgres import E2EPostgresChecker
from string import Template
from util.docker import E2EDockerDeployer
from util.kubernetes import E2EKubernetesDeployer
from urllib import request, parse
from typing import Iterator
from pathlib import Path
from dataclasses import replace
from contextlib import contextmanager
from util.images import E2EImagesDefinitions
from util.constant import E2EOtherDefinitions
from verifier.context import VerificationContext, VerificationResult, BaseVerifier


class E2ES00InfrastructureVerifier(BaseVerifier):
    def deploy(self, context: VerificationContext) -> None:
        self.step(
            f"verify {self.context.deployer} deployment prerequisites",
            self.infrastructure.verify_prerequisites,
        )
        self.step(
            "clean and deploy Envoy, middleware, AuthN/AuthZ, and five Biz services",
            self.infrastructure.redeploy,
        )

    class Deployment:
        project_root = E2EOtherDefinitions.PROJECT_ROOT
        port_range = E2EOtherDefinitions.LOCAL_PORT_RANGE

        def solana_chain_reference(self) -> str:
            """Derive the CAIP-2 reference from the live local validator genesis."""
            genesis_hash = self.json_rpc(self.solana_service, 8899, "getGenesisHash")
            if not isinstance(genesis_hash, str) or len(genesis_hash) < 32:
                raise RuntimeError(
                    f"local Solana validator returned invalid genesis: {genesis_hash!r}"
                )
            return genesis_hash[:32]

        def _authguard_runtime_config(self) -> str:
            management = E2EOtherDefinitions.management()
            values = {
                "KEYCLOAK_URL": self.service_url(self.keycloak_service, 8080, "http"),
                "JAEGER_URL": self.service_url(self.jaeger_service, 4317, "http"),
                "LDAP_URL": self.service_url(self.ldap_service, 389, "ldap"),
                "MOCK_IDP_URL": self.service_url(self.mock_idp_service, 8080, "http"),
                "ANVIL_URL": self.service_url(self.anvil_service, 8545, "http"),
                "SOLANA_REFERENCE": self.solana_chain_reference(),
                "REDIS_NODE": self.redis_node,
                "IAM_POSTGRES_URL": self.iam_postgres_url,
                "AUTHN_ISSUER": self.authn_issuer,
                "AUTHN_BROWSER_HOST": E2EOtherDefinitions.AUTHN_BROWSER_HOST,
                "AUTHN_HOST": E2EOtherDefinitions.AUTHN_HOST,
                "CUSTOMER_GROWTH_HOST": E2EOtherDefinitions.CUSTOMER_GROWTH_HOST,
                "CUSTOMER_GROWTH_FALLBACK_HOST": E2EOtherDefinitions.CUSTOMER_GROWTH_FALLBACK_HOST,
                "MGMT_PORT": management["port"],
                "METRICS_PATH": management["metrics"]["path"],
            }
            path = E2EOtherDefinitions.AUTHGUARD_CONFIG_DIR / "authguard.yaml"
            config = Template(path.read_text()).safe_substitute(values).rstrip("\n")
            self.context.state["authguard_config"] = yaml.safe_load(config)
            return config

        def _build_images(self) -> None:
            proxy = os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
            build_args: tuple[str, ...] = ()
            if proxy:
                parsed_proxy = parse.urlparse(proxy)
                if not parsed_proxy.hostname or not parsed_proxy.port:
                    raise ValueError(
                        "HTTPS_PROXY/HTTP_PROXY must include a host and port"
                    )
                proxy_host = parsed_proxy.hostname
                container_proxy = proxy
                if proxy_host in {"127.0.0.1", "localhost", "::1"}:
                    proxy_host = self.container_proxy_host
                    container_proxy = parse.urlunparse(
                        parsed_proxy._replace(
                            netloc=f"{proxy_host}:{parsed_proxy.port}"
                        )
                    )
                build_args = (
                    "--build-arg",
                    f"HTTPS_PROXY={container_proxy}",
                    "--build-arg",
                    f"HTTP_PROXY={container_proxy}",
                    "--build-arg",
                    f"MAVEN_PROXY_HOST={proxy_host}",
                    "--build-arg",
                    f"MAVEN_PROXY_PORT={parsed_proxy.port}",
                )
            use_prebuilt_images = os.getenv(
                "AUTHGUARD_E2E_USE_PREBUILT_IMAGES", "false"
            ).lower() in {"1", "true", "yes"}
            if use_prebuilt_images:
                if (
                    self.image_references["authguard"]
                    == E2EImagesDefinitions.DEFAULT_AUTHGUARD_IMAGE
                    or self.image_references["web"]
                    == E2EImagesDefinitions.DEFAULT_AUTHGUARD_WEB_IMAGE
                ):
                    raise ValueError(
                        "prebuilt E2E mode requires AUTHGUARD_E2E_AUTHGUARD_IMAGE and AUTHGUARD_E2E_WEB_IMAGE"
                    )
                self._pull_image(self.image_references["authguard"])
                self._pull_image(self.image_references["web"])
            else:
                self._run(
                    (
                        "docker",
                        "build",
                        "--network=host",
                        "--pull=false",
                        *build_args,
                        "-f",
                        str(
                            E2EOtherDefinitions.PROJECT_ROOT
                            / "deploy"
                            / "docker"
                            / "Dockerfile"
                        ),
                        *E2EImagesDefinitions.build_arguments(
                            E2EOtherDefinitions.PROJECT_ROOT
                            / "deploy/docker/Dockerfile",
                            self.environment,
                        ),
                        "--build-arg",
                        "AUTHGUARD_CARGO_FEATURES=web3",
                        "-t",
                        self.image_references["authguard"],
                        ".",
                    ),
                    cwd=E2EOtherDefinitions.PROJECT_ROOT,
                )
                ui_dir = E2EOtherDefinitions.PROJECT_ROOT / "web"
                self._run(
                    (
                        "docker",
                        "build",
                        "--network=host",
                        "--pull=false",
                        *build_args,
                        "-f",
                        str(ui_dir / "Dockerfile"),
                        "--build-arg",
                        f"NODE_IMAGE={self.environment['NODE_IMAGE']}",
                        "--build-arg",
                        f"WEB_IMAGE={self.environment['WEB_IMAGE']}",
                        "--build-arg",
                        f"VITE_REOWN_PROJECT_ID={os.getenv('VITE_REOWN_PROJECT_ID', '')}",
                        "-t",
                        self.image_references["web"],
                        str(ui_dir),
                    ),
                    cwd=E2EOtherDefinitions.PROJECT_ROOT,
                )
            if self.images.local_chain_images:
                chain_builds = (
                    (self.images.anvil, self.deploy_dir / "anvil" / "Dockerfile"),
                    (self.images.solana, self.deploy_dir / "solana" / "Dockerfile"),
                )
                for image, dockerfile in chain_builds:
                    self._run(
                        (
                            "docker",
                            "build",
                            "--network=host",
                            "--pull=false",
                            *build_args,
                            "-f",
                            str(dockerfile),
                            "--build-arg",
                            f"RUST_IMAGE={self.environment['RUST_IMAGE']}",
                            "-t",
                            image,
                            str(dockerfile.parent),
                        ),
                        cwd=E2EOtherDefinitions.PROJECT_ROOT,
                    )
            for component, image in self.workload_images.items():
                service_dir = (
                    self.deploy_dir
                    / E2EOtherDefinitions.WORKLOAD_DIRECTORIES[component]
                )
                image_build_args = E2EImagesDefinitions.build_arguments(
                    service_dir / "Dockerfile", self.environment
                )
                self._run(
                    (
                        "docker",
                        "build",
                        "--network=host",
                        "--pull=false",
                        *build_args,
                        *image_build_args,
                        "-f",
                        str(service_dir / "Dockerfile"),
                        "-t",
                        image,
                        ".",
                    ),
                    cwd=E2EOtherDefinitions.PROJECT_ROOT,
                )
            self._run(
                (
                    "docker",
                    "build",
                    "--network=host",
                    "--pull=false",
                    *build_args,
                    "--build-arg",
                    f"PYTHON_IMAGE={self.environment['PYTHON_IMAGE']}",
                    "-f",
                    str(self.deploy_dir / "mock-external-idp-service" / "Dockerfile"),
                    "-t",
                    self.image_references["mock-idp"],
                    ".",
                ),
                cwd=E2EOtherDefinitions.PROJECT_ROOT,
            )

        @property
        def management_port(self) -> int:
            return int(E2EOtherDefinitions.management()["port"])

        keycloak_service = "keycloak"
        postgresql_service = "postgresql"
        jaeger_service = "jaeger"
        ldap_service = "ldap"
        mock_idp_service = "mock-idp"
        anvil_service = "anvil"
        solana_service = "solana"
        authn_issuer = "urn:authguard:e2e:authn"

    class KubernetesDeployment(Deployment, E2EKubernetesDeployer):
        IMAGE_LOADER_ENV = "AUTHGUARD_E2E_KUBERNETES_IMAGE_LOADER"
        CLUSTER_ENV = "AUTHGUARD_E2E_KUBERNETES_CLUSTER"
        PLATFORM_ENV = "AUTHGUARD_E2E_PLATFORM"

        def __init__(self, context: VerificationContext) -> None:
            super().__init__(context)
            self.namespace = os.getenv(
                "AUTHGUARD_E2E_NAMESPACE", "e2e-authguard-system"
            )
            self.release = os.getenv("AUTHGUARD_E2E_RELEASE", "authguard")
            if not self.namespace.startswith("e2e-authguard-"):
                raise ValueError(
                    "AUTHGUARD_E2E_NAMESPACE must start with e2e-authguard-"
                )
            if not self.release:
                raise ValueError("AUTHGUARD_E2E_RELEASE must not be empty")
            self.envoy_release = "envoy"
            self.support_release = "customer-growth"
            self.authguard_release = self.release
            self.authguard_authz_service = self.authguard_release
            self.authguard_authn_service = f"{self.authguard_release}-authn"
            self.authn_route_name = "authn"
            self.gateway_name = "gateway"
            self.gateway_class_name = f"{self.namespace}-gateway"
            self.envoy_gateway_deployment = "envoy-gateway"
            self.envoy_proxy_deployment = "envoygateway"
            self.redis_service = f"{self.release}-redis"
            self.environment.update(
                {
                    "KUBECONFIG": self._resolve_kubeconfig(),
                    "AUTHGUARD_E2E_CLUSTER_RESOURCE_PREFIX": self.namespace,
                }
            )
            self.helm_chart = (
                E2EOtherDefinitions.PROJECT_ROOT / "deploy" / "helm" / "authguard"
            )
            self.support_chart = (
                E2EOtherDefinitions.E2E_DIR / "deploy" / "authguard" / "helm"
            )
            self.deploy_dir = E2EOtherDefinitions.E2E_DIR / "deploy"
            self._image_loader: E2EKubernetesDeployer._LocalImageLoader | None = None
            self.deploy_dir = E2EOtherDefinitions.DEPLOY_DIR
            self.releases = (
                *[
                    E2EOtherDefinitions.COMPONENTS[key]
                    for key in reversed(E2EOtherDefinitions.SUPPORT_COMPONENTS)
                ],
                self.authguard_release,
                self.support_release,
                self.envoy_release,
            )

        @property
        def principal_discovery_secret(self) -> str:
            return "principal-discovery-credentials"

        @property
        def authguard_web_service(self) -> str:
            return f"{self.authguard_release}-web"

        @property
        def authguard_web_route(self) -> str:
            return "web"

        @property
        def gateway_controller_name(self) -> str:
            """Controller identity dedicated to this isolated E2E GatewayClass."""
            return f"e2e.authguard.io/{self.gateway_class_name}"

        def workload_service(self, component: str) -> str:
            return component

        @property
        def issuer(self) -> str:
            return f"http://{self.keycloak_service}.{self.namespace}.svc.cluster.local:8080/realms/example-corp"

        @property
        def redis_node(self) -> str:
            return (
                f"redis://{self.redis_service}.{self.namespace}.svc.cluster.local:6379"
            )

        @property
        def iam_postgres_url(self) -> str:
            return f"postgresql://{self.internal_hostname(self.postgresql_service)}:5432/e2e_authguard_customer_growth?sslmode=disable&options=-csearch_path%3Dauthguard"

        def redeploy(self) -> None:
            self._run(("helm", "dependency", "list", str(self.helm_chart)))
            self._run(("helm", "dependency", "list", str(self.support_chart)))
            if self.context.clean:
                self.cleanup()
            self._run(
                ("kubectl", "create", "namespace", self.namespace), allowed_codes={0, 1}
            )
            if self.context.build_images:
                self._build_images()
            self._prepare_external_images()
            self._install_envoy_gateway()
            self._remove_mutable_cluster_images()
            self._prepare_workload_images()
            self._install_support_services()
            self._prepare_external_images()
            self._prepare_workload_images()
            self._wait_for_support_services()
            self._import_image(self.image_references["authguard"])
            self._import_image(self.image_references["web"])
            self._import_image(self.images.redis)
            self._install_authguard()
            self._wait_for_resources()

        def _prepare_external_images(self) -> None:
            loader = self._local_image_loader()
            cluster_images = loader.cached_images()
            for image in self.images.pullable_images:
                if image in cluster_images and loader.kind != "docker":
                    self.details.append(f"reuse {loader.description} image: {image}")
                    continue
                self._ensure_local_image(image)
                self._import_image(image)

        def _prepare_workload_images(self) -> None:
            for image in (
                *self.workload_images.values(),
                self.image_references["mock-idp"],
                self.image_references["web"],
                *self.images.local_chain_images,
            ):
                self._import_image(image)

        def _remove_mutable_cluster_images(self) -> None:
            """Prevent a recreated Pod from starting an obsolete mutable E2E image tag."""
            loader = self._local_image_loader()
            for image in (
                *self.workload_images.values(),
                self.image_references["mock-idp"],
                self.image_references["web"],
                *self.images.local_chain_images,
            ):
                loader.remove_image(image)

        def _install_component(
            self, component: str, release: str, values: dict, *options: str
        ) -> None:
            self.helm_install(
                release,
                E2EOtherDefinitions.chart(component),
                E2EOtherDefinitions.select(values, component),
                *options,
            )

        def _install_envoy_gateway(self) -> None:
            values = E2EOtherDefinitions.values(self.environment)
            gateway = values["envoy_gateway"]
            gateway.setdefault("config", {}).setdefault("envoyGateway", {}).setdefault(
                "gateway", {}
            )["controllerName"] = self.gateway_controller_name
            for image in gateway["global"]["images"].values():
                image["pullPolicy"] = "Never"
            self._install_component(
                "envoy_gateway",
                self.envoy_release,
                values,
                "--post-renderer",
                str(self.deploy_dir / "envoy-gateway/helm/post_renderer.py"),
                "--wait",
                f"--timeout={self.context.timeout_seconds}s",
            )

        def _install_support_services(self) -> None:
            values = E2EOtherDefinitions.values(self.environment)
            values["authguard"][
                "grpcTarget"
            ] = f"{self.authguard_release}.{self.namespace}.svc.cluster.local:8081"
            values["gateway"]["name"] = self.gateway_name
            values["redis_cluster"]["fullnameOverride"] = self.redis_service
            self._install_component("authguard", self.support_release, values)
            for component in E2EOtherDefinitions.SUPPORT_COMPONENTS:
                self._install_component(
                    component, E2EOtherDefinitions.COMPONENTS[component], values
                )

        def _wait_for_support_services(self) -> None:
            """Wait until every support/workload Deployment has consumed its image."""
            for deployment in (
                self.keycloak_service,
                self.ldap_service,
                self.jaeger_service,
                self.postgresql_service,
                self.mock_idp_service,
                self.anvil_service,
                self.solana_service,
                *[
                    self.workload_service(component)
                    for component in self.workload_images
                ],
            ):
                self._run(
                    (
                        "kubectl",
                        "rollout",
                        "status",
                        f"deployment/{deployment}",
                        "-n",
                        self.namespace,
                        f"--timeout={self.context.timeout_seconds}s",
                    )
                )

        def _install_authguard(self) -> None:
            authguard_values = self._authguard_values()
            authguard_values["enabled"] = True
            values = {
                "support": {"enabled": False},
                "authguard-middleware": authguard_values,
                "global": {
                    "authguard": {
                        "themeRevision": "v1",
                        "themeConfigMap": "{{ .Release.Name }}-authguard-theme-{{ .Values.global.authguard.themeRevision }}",
                    }
                },
            }
            self._install_component(
                "authguard",
                self.authguard_release,
                values,
                "--wait",
                f"--timeout={self.context.timeout_seconds}s",
            )

        def _authguard_values(self) -> dict:
            authguard_config = self._authguard_runtime_config()
            redis_registry, redis_repository, redis_tag = self.images.helm_image_parts(
                self.images.redis
            )
            return {
                "theme": {"files": "files/authguard-theme/*"},
                "envoy_gateway": {
                    "enabled": False,
                    "fullnameOverride": self.envoy_gateway_deployment,
                    "global": {
                        "images": {
                            "envoyProxy": {
                                "image": self.images.envoy,
                                "pullPolicy": "Never",
                            }
                        }
                    },
                    "ext_authz": {
                        "enabled": True,
                        "gateway": {
                            "create": True,
                            "className": self.gateway_class_name,
                            "name": self.gateway_name,
                            "listenerPort": 8082,
                            "envoyDeploymentName": self.envoy_proxy_deployment,
                            "controllerName": self.gateway_controller_name,
                        },
                        "authguardRoute": {"enabled": False},
                        "authnRoute": {
                            "enabled": True,
                            "name": self.authn_route_name,
                            "hostnames": [
                                E2EOtherDefinitions.AUTHN_HOST,
                                E2EOtherDefinitions.AUTHN_BROWSER_HOST,
                                E2EOtherDefinitions.CUSTOMER_GROWTH_HOST,
                                E2EOtherDefinitions.CUSTOMER_GROWTH_FALLBACK_HOST,
                            ],
                        },
                        "tracing": {
                            "enabled": True,
                            "backendRef": {"name": self.jaeger_service, "port": 4317},
                            "serviceName": "envoygateway",
                        },
                    },
                },
                "redis_cluster": {
                    "enabled": False,
                    "fullnameOverride": self.redis_service,
                    "image": {
                        "registry": redis_registry,
                        "repository": redis_repository,
                        "tag": redis_tag,
                        "pullPolicy": "IfNotPresent",
                    },
                    "existingSecret": self.principal_discovery_secret,
                    "existingSecretPasswordKey": "AUTHGUARD__CACHE__REDIS__PASSWORD",
                    "cluster": {"nodes": 6, "replicas": 1},
                    "persistence": {"enabled": False},
                },
                "postgresql": {"enabled": False},
                "fullnameOverride": self.authguard_release,
                "secrets": {
                    "provider": "kubernetes",
                    "kubernetes": {"existingSecret": self.principal_discovery_secret},
                },
                "authguard": {
                    "authn": {
                        "enabled": True,
                        "replicaCount": 1,
                        "resources": {
                            "requests": {"cpu": "100m", "memory": "128Mi"},
                            "limits": {"cpu": "1000m", "memory": "768Mi"},
                        },
                        "image": {
                            "repository": self.image_references["authguard"].rsplit(
                                ":", 1
                            )[0],
                            "tag": self.image_references["authguard"].rsplit(":", 1)[1],
                            "pullPolicy": "Never",
                        },
                        "disruptionBudget": {"enabled": False},
                        "canonical_jwt": {
                            "issuer": self.authn_issuer,
                            "audiences": ["customer-growth-job-service"],
                            "local_jwks": {
                                "existing_config_map": f"{self.keycloak_service}-realm-jwks",
                                "inline": "",
                            },
                            "remote_jwks": {"uri": "", "backend_refs": []},
                        },
                    },
                    "web": {
                        "enabled": True,
                        "replicaCount": 1,
                        "image": {
                            "repository": self.image_references["web"].rsplit(":", 1)[
                                0
                            ],
                            "tag": self.image_references["web"].rsplit(":", 1)[1],
                            "pullPolicy": "Never",
                        },
                        "route": {
                            "enabled": True,
                            "name": self.authguard_web_route,
                            "hostnames": [
                                E2EOtherDefinitions.AUTHN_HOST,
                                E2EOtherDefinitions.AUTHN_BROWSER_HOST,
                                E2EOtherDefinitions.CUSTOMER_GROWTH_HOST,
                                E2EOtherDefinitions.CUSTOMER_GROWTH_FALLBACK_HOST,
                            ],
                            "dashboard": {
                                "enabled": True,
                                "name": f"{self.authguard_web_route}-dashboard",
                                "hostnames": [
                                    E2EOtherDefinitions.AUTHN_HOST,
                                    E2EOtherDefinitions.AUTHN_BROWSER_HOST,
                                ],
                            },
                        },
                    },
                    "authz": {
                        "replicaCount": 1,
                        "image": {
                            "repository": self.image_references["authguard"].rsplit(
                                ":", 1
                            )[0],
                            "tag": self.image_references["authguard"].rsplit(":", 1)[1],
                            "pullPolicy": "Never",
                        },
                        "disruptionBudget": {"enabled": False},
                        "api": {"enabled": True},
                    },
                    "mgmt": {
                        "enabled": True,
                        "otelEnabled": True,
                        "otelEndpoint": f"http://{self.jaeger_service}.{self.namespace}.svc.cluster.local:4317",
                    },
                    "authguard-config": authguard_config,
                    "mgmt": {"enabled": True, "port": self.management_port},
                },
            }

        def _wait_for_resources(self) -> None:
            for deployment in (
                self.envoy_gateway_deployment,
                self.keycloak_service,
                self.ldap_service,
                self.jaeger_service,
                self.postgresql_service,
                self.mock_idp_service,
                self.anvil_service,
                self.solana_service,
                *[
                    self.workload_service(component)
                    for component in self.workload_images
                ],
                self.authguard_release,
                f"{self.authguard_release}-authn",
                self.authguard_web_service,
            ):
                self._run(
                    (
                        "kubectl",
                        "rollout",
                        "status",
                        f"deployment/{deployment}",
                        "-n",
                        self.namespace,
                        f"--timeout={self.context.timeout_seconds}s",
                    )
                )
            self._run(
                (
                    "kubectl",
                    "wait",
                    "deployment",
                    "-n",
                    self.namespace,
                    "-l",
                    f"gateway.envoyproxy.io/owning-gateway-name={self.gateway_name}",
                    "--for=condition=Available",
                    f"--timeout={self.context.timeout_seconds}s",
                )
            )

        def _envoy_proxy_service(self) -> str:
            result = self._run(
                (
                    "kubectl",
                    "get",
                    "services",
                    "-n",
                    self.namespace,
                    "-l",
                    f"gateway.envoyproxy.io/owning-gateway-name={self.gateway_name}",
                    "-o",
                    "jsonpath={.items[0].metadata.name}",
                )
            )
            service = result.output.strip()
            if not service:
                raise RuntimeError("Envoy Proxy service was not created")
            return service

        @contextmanager
        def _forward_envoy_admin(self) -> Iterator[int]:
            payload = json.loads(
                self._run(
                    (
                        "kubectl",
                        "get",
                        "pods",
                        "-n",
                        self.namespace,
                        "-l",
                        f"gateway.envoyproxy.io/owning-gateway-name={self.gateway_name}",
                        "-o",
                        "json",
                    )
                ).output
            )
            ready = [
                item
                for item in payload.get("items", [])
                if item.get("status", {}).get("phase") == "Running"
                and any(
                    (
                        condition.get("type") == "Ready"
                        and condition.get("status") == "True"
                        for condition in item.get("status", {}).get("conditions", [])
                    )
                )
            ]
            if not ready:
                raise RuntimeError("no ready Envoy Proxy pod was created")
            pod = (
                max(
                    ready,
                    key=lambda item: item.get("metadata", {}).get(
                        "creationTimestamp", ""
                    ),
                )
                .get("metadata", {})
                .get("name", "")
            )
            if not pod:
                raise RuntimeError("ready Envoy Proxy pod has no name")
            with self._forward_resource(f"pod/{pod}", 19000) as port:
                yield port

        def postgresql_query(self, sql: str) -> str:
            pod = self._run(
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    self.namespace,
                    "-l",
                    "app.kubernetes.io/component=postgresql",
                    "-o",
                    "jsonpath={.items[0].metadata.name}",
                )
            ).output.strip()
            return self._run(
                (
                    "kubectl",
                    "exec",
                    "-n",
                    self.namespace,
                    pod,
                    "--",
                    *E2EPostgresChecker.command(
                        sql,
                        schema="authguard",
                        database_variable="POSTGRESQL_DATABASE",
                        password_variable="POSTGRESQL_POSTGRES_PASSWORD",
                    ),
                )
            ).output.strip()

    class DockerDeployment(Deployment, E2EDockerDeployer):
        def __init__(self, context: VerificationContext) -> None:
            super().__init__(
                context,
                project_name=os.getenv(
                    "AUTHGUARD_E2E_DOCKER_PROJECT", "e2e-authguard-customer-growth"
                ),
                compose_file=E2EOtherDefinitions.E2E_DIR / "docker-compose.yaml",
                runtime_dir=E2EOtherDefinitions.REPORTS_DIR / ".runtime/docker",
            )
            self.project_name = os.getenv(
                "AUTHGUARD_E2E_DOCKER_PROJECT", "e2e-authguard-customer-growth"
            )
            if not self.project_name.startswith("e2e-authguard-"):
                raise ValueError(
                    "AUTHGUARD_E2E_DOCKER_PROJECT must start with e2e-authguard-"
                )
            self.namespace = self.project_name
            self.release = self.project_name
            self.support_release = self.project_name
            self.authguard_release = "authz"
            self.authguard_authz_service = "authz"
            self.authguard_authn_service = "authn"
            self.authguard_web_service = "web"
            self.principal_discovery_secret = "authguard.env"
            self.environment.update(
                {"AUTHGUARD_E2E_RUNTIME_DIR": str(self.runtime_dir)}
            )
            if "DOCKER_HOST" in os.environ:
                self.environment["DOCKER_HOST"] = os.environ["DOCKER_HOST"]
            elif (
                not Path("/var/run/docker.sock").exists()
                and Path("/run/podman/podman.sock").exists()
            ):
                self.environment["DOCKER_HOST"] = "unix:///run/podman/podman.sock"
            self.deploy_dir = E2EOtherDefinitions.DEPLOY_DIR
            self.cleanup_image = self.images.postgres
            self.environment["AUTHGUARD_E2E_MGMT_PORT"] = str(self.management_port)

        @property
        def issuer(self) -> str:
            return "http://keycloak:8080/realms/example-corp"

        @property
        def redis_node(self) -> str:
            return "redis://redis:6379"

        @property
        def iam_postgres_url(self) -> str:
            return "postgresql://postgresql:5432/e2e_authguard_customer_growth?sslmode=disable&options=-csearch_path%3Dauthguard"

        def workload_service(self, component: str) -> str:
            if component not in self.workload_images:
                raise ValueError(f"unknown workload: {component}")
            return component

        def verify_prerequisites(self) -> None:
            self.require_executables("docker")
            self._run(("docker", "version"))
            self.detect_runtime()
            self._run(("docker", "compose", "version"))
            self._prepare_runtime_files()
            self._compose("config", "--quiet")

        def redeploy(self) -> None:
            if self.context.clean:
                self.cleanup()
            if self.context.build_images:
                self._build_images()
            for image in self.images.docker_pullable_images:
                self._ensure_local_image(image)
            self._prepare_runtime_files()
            support_services = (
                "postgresql",
                "redis",
                "keycloak",
                "ldap",
                "jaeger",
                "mock-idp",
                "anvil",
                "solana",
            )
            self._compose("up", "-d", *support_services)
            self._wait_for_support_services()
            (self.runtime_dir / "authguard.yaml").write_text(
                self._authguard_runtime_config() + "\n", encoding="utf-8"
            )
            self._compose("up", "-d", "--remove-orphans")
            self._wait_for_runtime_services()

        @contextmanager
        def _forward_envoy_admin(self) -> Iterator[int]:
            with self._forward_service("envoy", 19000) as port:
                yield port

        def _envoy_proxy_service(self) -> str:
            return "envoy"

        def postgresql_query(self, sql: str) -> str:
            return self._compose(
                "exec",
                "-T",
                self.postgresql_service,
                *E2EPostgresChecker.command(
                    sql,
                    schema="authguard",
                    database_variable="POSTGRESQL_DATABASE",
                    password_variable="POSTGRESQL_POSTGRES_PASSWORD",
                ),
            ).output.strip()

        def verify_infrastructure_contract(self) -> None:
            """Verify Docker owns the same real services and trust boundaries as Helm."""
            expected_services = {
                "postgresql",
                "redis",
                "keycloak",
                "ldap",
                "jaeger",
                "mock-idp",
                "anvil",
                "solana",
                "authz",
                "authn",
                "web",
                "envoy",
                *self.workload_images,
            }
            container_ids = re.findall(
                "(?m)(?:^|\\x1b\\[0m)([0-9a-f]{12,64})$",
                self._compose("ps", "-q").output,
            )
            if not container_ids:
                raise RuntimeError("Docker Compose returned no E2E containers")
            containers = json.loads(
                self._run(("docker", "inspect", *container_ids)).output
            )
            by_service = {
                container.get("Config", {})
                .get("Labels", {})
                .get("com.docker.compose.service"): container
                for container in containers
            }
            if missing := (expected_services - set(by_service)):
                raise RuntimeError(
                    f"Docker E2E services are missing: {sorted(missing)}"
                )
            not_running = {
                service: by_service[service].get("State", {}).get("Status")
                for service in expected_services
                if by_service[service].get("State", {}).get("Status") != "running"
            }
            if not_running:
                raise RuntimeError(
                    f"Docker E2E services are not running: {not_running}"
                )
            restarted = {
                service: int(by_service[service].get("RestartCount", 0))
                for service in expected_services
            }
            if failures := {name: count for name, count in restarted.items() if count}:
                raise RuntimeError(f"Docker E2E containers restarted: {failures}")
            web = by_service["web"]
            destinations = {mount["Destination"] for mount in web.get("Mounts", [])}
            theme_path = "/usr/share/nginx/html/assets/themes/custom"
            if theme_path not in destinations:
                raise RuntimeError(
                    "Docker Web container does not mount the local theme directory"
                )
            for service in ("authn", "authz"):
                inspected = by_service[service]
                if theme_path in {
                    mount["Destination"] for mount in inspected.get("Mounts", [])
                }:
                    raise RuntimeError(
                        f"theme assets leaked into Docker service {service}"
                    )
            if self.json_rpc("anvil", 8545, "eth_chainId") != hex(31337):
                raise RuntimeError("Docker Anvil did not expose chain 31337")
            if self.json_rpc("solana", 8899, "getHealth") != "ok":
                raise RuntimeError("Docker Solana test validator is unhealthy")
            self.details.append(
                "Docker Compose runs the real identity stores, local chains, AuthGuard, Envoy, and five business services; the local custom theme is mounted only into Web"
            )

        def _prepare_runtime_files(self) -> None:
            self.runtime_dir.mkdir(parents=True, exist_ok=True)
            (self.runtime_dir / "authguard.yaml").write_text(
                "# rendered after support startup\n"
            )
            self._write_authguard_environment()
            self._write_keycloak_realm()
            self._write_ldap_config()
            postgres_init = self.runtime_dir / "postgres-init.sh"
            postgres_init.write_text(self._postgres_init_script(), encoding="utf-8")
            postgres_init.chmod(493)

        def _write_authguard_environment(self) -> None:
            signing_key = (
                E2EOtherDefinitions.AUTHGUARD_JWT_KEYS_DIR / "realm-signing-key.pem"
            ).read_bytes()
            resign_key = (
                E2EOtherDefinitions.AUTHGUARD_JWT_KEYS_DIR / "resign-jwt-key.pem"
            ).read_bytes()
            values = {
                "AUTHGUARD__AUTHN__PROVIDERS__E2E_AUTHGUARD_KEYCLOAK__CLIENT_SECRET": "e2e-authguard-principal-discovery-client-secret",
                "AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__KEYCLOAK__INDEX_0__AUTH__CLIENT_SECRET": "e2e-authguard-principal-discovery-client-secret",
                "AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__LDAP__INDEX_0__AUTH__BIND_PASSWORD": "e2e-authguard-ldap-bind-password",
                "AUTHGUARD__AUTHN__PROVIDERS__GITHUB__CLIENT_SECRET": "e2e-authguard-github-secret",
                "AUTHGUARD__AUTHN__PROVIDERS__GOOGLE__CLIENT_SECRET": "e2e-authguard-google-secret",
                "AUTHGUARD__AUTHN__PROVIDERS__WECHAT__CLIENT_SECRET": "e2e-authguard-wechat-secret",
                "AUTHGUARD__AUTHN__PROVIDERS__QQ__CLIENT_SECRET": "e2e-authguard-qq-secret",
                "AUTHGUARD__AUTHN__STANDALONE__CREDENTIAL_ENCRYPTION_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
                "AUTHGUARD__STORAGE__POSTGRES__PASSWORD": "e2e-authguard-postgres-password",
                "AUTHGUARD__CACHE__REDIS__PASSWORD": "e2e-authguard-redis-password",
                "AUTHGUARD__AUTHZ__API__TOKEN": "e2e-authguard-api-token",
                "AUTHGUARD__AUTHZ__SCOPE_DELIVERY__DIRECT_CONTEXT_HMAC_KEY": "e2e-authguard-access-context-hmac-key",
                "AUTHGUARD__AUTHN__TOKEN__PRIVATE_KEY_B64": base64.b64encode(
                    signing_key
                ).decode(),
                "AUTHGUARD__AUTHZ__RESIGN__PRIVATE_KEY_B64": base64.b64encode(
                    resign_key
                ).decode(),
            }
            content = "".join((f"{key}={value}\n" for key, value in values.items()))
            target = self.runtime_dir / "authguard.env"
            target.write_text(content, encoding="utf-8")
            target.chmod(384)

        def _write_keycloak_realm(self) -> None:
            source = json.loads(
                E2EOtherDefinitions.KEYCLOAK_REALM_PATH.read_text(encoding="utf-8")
            )
            replacements = {
                "${E2E_AUTHGUARD_REALM_SIGNING_PRIVATE_KEY}": (
                    E2EOtherDefinitions.AUTHGUARD_JWT_KEYS_DIR / "realm-signing-key.pem"
                ).read_text(encoding="utf-8"),
                "${E2E_AUTHGUARD_REALM_SIGNING_CERTIFICATE}": (
                    E2EOtherDefinitions.AUTHGUARD_JWT_KEYS_DIR
                    / "realm-signing-cert.pem"
                ).read_text(encoding="utf-8"),
                "${E2E_AUTHGUARD_PRINCIPAL_DISCOVERY_CLIENT_SECRET}": "e2e-authguard-principal-discovery-client-secret",
                "${E2E_AUTHGUARD_WORKLOAD_CLIENT_SECRET}": "e2e-authguard-workload-client-secret",
            }

            def replace(value: object) -> object:
                if isinstance(value, str):
                    for marker, replacement in replacements.items():
                        value = value.replace(marker, replacement)
                    return value
                if isinstance(value, list):
                    return [replace(item) for item in value]
                if isinstance(value, dict):
                    return {key: replace(item) for key, item in value.items()}
                return value

            target = self.runtime_dir / "keycloak" / "e2e-realm.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(replace(source), indent=2) + "\n", encoding="utf-8"
            )

        def _write_ldap_config(self) -> None:
            bind_hash = hashlib.sha256(b"e2e-authguard-ldap-bind-password").hexdigest()
            config = (
                E2EOtherDefinitions.E2E_DIR / "deploy/ldap/source/config.cfg"
            ).read_text()
            (self.runtime_dir / "ldap-config.cfg").write_text(
                config.replace("@LDAP_BIND_PASSWORD_SHA256@", json.dumps(bind_hash)),
                encoding="utf-8",
            )

        @staticmethod
        def _postgres_init_script() -> str:
            roles = {
                "e2e_authguard_service": (
                    "e2e-authguard-postgres-password",
                    "authguard",
                ),
                "e2e_authguard_customer_growth_go_sqlx": (
                    "e2e-authguard-customer-growth-go-sqlx-password",
                    "e2e_authguard_customer_growth_go_sqlx",
                ),
                "e2e_authguard_customer_growth_rust_sqlx": (
                    "e2e-authguard-customer-growth-rust-sqlx-password",
                    "e2e_authguard_customer_growth_rust_sqlx",
                ),
                "e2e_authguard_customer_growth_python_sqlalchemy": (
                    "e2e-authguard-customer-growth-python-sqlalchemy-password",
                    "e2e_authguard_customer_growth_python_sqlalchemy",
                ),
                "e2e_authguard_customer_growth_spring_jdbc": (
                    "e2e-authguard-customer-growth-spring-jdbc-password",
                    "e2e_authguard_customer_growth_spring_jdbc",
                ),
                "e2e_authguard_customer_growth_spring_jpa": (
                    "e2e-authguard-customer-growth-spring-jpa-password",
                    "e2e_authguard_customer_growth_spring_jpa",
                ),
            }
            lines = [
                "#!/bin/bash",
                "set -euo pipefail",
                'export PGPASSWORD="$POSTGRESQL_POSTGRES_PASSWORD"',
            ]
            for role, (password, schema) in roles.items():
                lines.extend(
                    (
                        f"""psql --host=127.0.0.1 --username=postgres --dbname="$POSTGRESQL_DATABASE" --set=ON_ERROR_STOP=1 --set=role_name='{role}' --set=role_password='{password}' --set=schema_name='{schema}' <<'SQL'""",
                        "SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'role_name', :'role_password') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role_name') \\gexec",
                        "SELECT format('CREATE SCHEMA IF NOT EXISTS %I AUTHORIZATION %I', :'schema_name', :'role_name') \\gexec",
                        "SELECT format('ALTER ROLE %I IN DATABASE %I SET search_path = %I', :'role_name', current_database(), :'schema_name') \\gexec",
                        "SQL",
                    )
                )
                if schema != "authguard":
                    lines.append(
                        f"""PGPASSWORD='{password}' PGOPTIONS='-c search_path={schema}' psql --host=127.0.0.1 --username='{role}' --dbname="$POSTGRESQL_DATABASE" --set=ON_ERROR_STOP=1 --file=/e2e-seed/init.sql"""
                    )
            return "\n".join(lines) + "\n"

        def _wait_for_support_services(self) -> None:
            for service, port in (
                ("postgresql", 5432),
                ("redis", 6379),
                ("keycloak", 8080),
                ("ldap", 389),
                ("jaeger", 16686),
                ("mock-idp", 8080),
                ("anvil", 8545),
                ("solana", 8899),
            ):
                self._wait_for_tcp(service, port)
            self._wait_for_http(
                "keycloak",
                8080,
                "/realms/example-corp/.well-known/openid-configuration",
            )
            self._wait_for_http("mock-idp", 8080, "/healthz")
            self._wait_for_json_rpc("anvil", 8545, "eth_chainId")
            self._wait_for_json_rpc("solana", 8899, "getHealth")

        def _wait_for_runtime_services(self) -> None:
            self._wait_for_http("authn", self.management_port, "/healthz")
            self._wait_for_http("authz", self.management_port, "/healthz")
            self._wait_for_http("web", 8080, "/auth/login")
            for service in self.workload_images:
                self._wait_for_http(service, 8080, "/healthz")
            self._wait_for_tcp("envoy", 8082)

    def init(self, context: VerificationContext) -> None:
        """No additional scenario test data initialization is required."""

    scenario_id = "00"
    title = "Infrastructure: deployment and middleware initialization"

    def verifier(self, context: VerificationContext) -> VerificationResult:
        return self.execute(self._run_scenario)

    def _run_scenario(self) -> None:
        if self.context.deployer == "docker":
            self.step(
                "verify Docker Compose services, local theme mount, chains, and restart state",
                self.infrastructure.verify_infrastructure_contract,
            )
            self.step("verify AuthGuard IAM schema migrations", self._verify_iam_schema)
            return
        self.step(
            "verify the business Chart keeps AuthGuard opt-in and mounts its local theme files",
            self._verify_business_chart_authguard_integration,
        )
        self.step(
            "verify the isolated E2E namespace and component naming contract",
            self._verify_namespace_and_pod_names,
        )
        self.step(
            "wait for accepted Gateway API resources",
            self._wait_for_gateway_api_acceptance,
        )
        self.step(
            "verify Keycloak, LDAP, mock IdP, and Secret initialization",
            self._verify_identity_middleware_initialization,
        )
        self.step(
            "verify disposable Anvil and Solana nodes through real JSON-RPC",
            self._verify_wallet_nodes,
        )
        self.step("verify Redis Cluster health", self._verify_redis_cluster)
        self.step("verify immutable running images", self._verify_running_images)
        self.step(
            "verify zero container restarts", self._verify_zero_container_restarts
        )
        self.step("verify AuthGuard IAM schema migrations", self._verify_iam_schema)

    def _verify_business_chart_authguard_integration(self) -> None:
        """Prove one business Chart owns local theme files and an optional subchart."""
        default_theme_name = f"{self.support_release}-authguard-theme-v1"
        default_theme = self._run(
            (
                "kubectl",
                "get",
                "configmap",
                default_theme_name,
                "-n",
                self.namespace,
                "--ignore-not-found",
                "-o",
                "name",
            )
        ).output.strip()
        if default_theme:
            raise RuntimeError(
                "the normal business release rendered AuthGuard theme resources by default"
            )
        theme_name = f"{self.authguard_release}-authguard-theme-v1"
        theme = json.loads(
            self._run(
                (
                    "kubectl",
                    "get",
                    "configmap",
                    theme_name,
                    "-n",
                    self.namespace,
                    "-o",
                    "json",
                )
            ).output
        )
        if theme.get("immutable") is not True or set(theme.get("data", {})) != {
            "customer-growth.css",
            "customer-growth.svg",
        }:
            raise RuntimeError(
                "business Chart did not package the exact local login-theme directory"
            )
        if (
            theme.get("metadata", {})
            .get("annotations", {})
            .get("meta.helm.sh/release-name")
            != self.authguard_release
        ):
            raise RuntimeError(
                "local Theme ConfigMap is not owned by the middleware release"
            )
        web = json.loads(
            self._run(
                (
                    "kubectl",
                    "get",
                    "deployment",
                    self.authguard_web_service,
                    "-n",
                    self.namespace,
                    "-o",
                    "json",
                )
            ).output
        )
        pod_spec = web["spec"]["template"]["spec"]
        custom_theme = next(
            (
                volume.get("configMap", {}).get("name")
                for volume in pod_spec.get("volumes", [])
                if volume.get("name") == "custom-themes"
            ),
            None,
        )
        if custom_theme != theme_name or pod_spec.get("initContainers"):
            raise RuntimeError(
                "AuthGuard Web did not mount the business ConfigMap directly or added an unexpected init container"
            )
        deployments = json.loads(
            self._run(
                (
                    "kubectl",
                    "get",
                    "deployment",
                    self.authguard_release,
                    f"{self.authguard_release}-authn",
                    "-n",
                    self.namespace,
                    "-o",
                    "json",
                )
            ).output
        )["items"]
        for deployment in deployments:
            spec = deployment["spec"]["template"]["spec"]
            if any(
                (
                    volume.get("name") == "custom-themes"
                    for volume in spec.get("volumes", [])
                )
            ) or any(
                (
                    mount.get("name") == "custom-themes"
                    for container in spec.get("containers", [])
                    for mount in container.get("volumeMounts", [])
                )
            ):
                raise RuntimeError(
                    f"theme assets leaked into non-Web deployment {deployment['metadata']['name']}"
                )
        self.details.append(
            "normal business Helm release left authguard.enabled=false; the separate opt-in middleware release rendered the vendored AuthGuard tgz and mounted two local Chart files only in AuthGuard Web, without building a theme image"
        )

    def _verify_namespace_and_pod_names(self) -> None:
        """Keep E2E-owned resources obvious during interactive review and cleanup."""
        if self.namespace != "e2e-authguard-system":
            raise RuntimeError(
                f"the Kubernetes E2E default namespace must be e2e-authguard-system; received {self.namespace!r}"
            )
        pods = json.loads(
            self._run(
                ("kubectl", "get", "pods", "-n", self.namespace, "-o", "json")
            ).output
        )
        names = sorted(
            (item.get("metadata", {}).get("name", "") for item in pods.get("items", []))
        )
        expected_prefixes = (
            f"{self.authguard_release}-",
            f"{self.envoy_gateway_deployment}-",
            f"{self.envoy_proxy_deployment}-",
            f"{self.keycloak_service}-",
            f"{self.ldap_service}-",
            f"{self.jaeger_service}-",
            f"{self.postgresql_service}-",
            f"{self.mock_idp_service}-",
            f"{self.anvil_service}-",
            f"{self.solana_service}-",
            f"{self.redis_service}-",
            *[
                f"{self.workload_service(component)}-"
                for component in self.workload_images
            ],
        )
        unexpected = [name for name in names if not name.startswith(expected_prefixes)]
        if unexpected:
            raise RuntimeError(
                f"E2E namespace contains non-component Pod names: {unexpected}; expected prefixes={expected_prefixes}"
            )
        if not any(
            (name.startswith(f"{self.envoy_proxy_deployment}-") for name in names)
        ):
            raise RuntimeError(
                f"Envoy Gateway did not create its generated data-plane Pod with the expected {self.envoy_proxy_deployment!r} prefix"
            )
        self.details.append(
            "the e2e-authguard-system namespace isolates the suite while every Pod uses its normal component name; the generated Envoy data plane is envoygateway-*"
        )

    def _verify_identity_middleware_initialization(self) -> None:
        """Verify that enterprise directories and OAuth test IdPs initialized."""
        deployments = json.loads(
            self._run(
                (
                    "kubectl",
                    "get",
                    "deployment",
                    self.keycloak_service,
                    self.ldap_service,
                    self.mock_idp_service,
                    "-n",
                    self.namespace,
                    "-o",
                    "json",
                )
            ).output
        )["items"]
        by_name = {item["metadata"]["name"]: item for item in deployments}
        keycloak = by_name[self.keycloak_service]["spec"]["template"]["spec"][
            "containers"
        ][0]
        keycloak_env = {item["name"] for item in keycloak.get("env", [])}
        if "--import-realm" not in keycloak.get("args", []) or not {
            "E2E_AUTHGUARD_PRINCIPAL_DISCOVERY_CLIENT_SECRET",
            "E2E_AUTHGUARD_WORKLOAD_CLIENT_SECRET",
        }.issubset(keycloak_env):
            raise RuntimeError(
                "Keycloak realm/client bootstrap configuration is incomplete"
            )
        ldap = by_name[self.ldap_service]["spec"]["template"]["spec"]
        ldap_container = ldap["containers"][0]
        secret_names = {
            volume.get("secret", {}).get("secretName")
            for volume in ldap.get("volumes", [])
        }
        if (
            not any(
                (
                    port.get("containerPort") == 389
                    for port in ldap_container.get("ports", [])
                )
            )
            or "ldap-credentials" not in secret_names
        ):
            raise RuntimeError(
                "LDAP scenario data/bind-secret bootstrap configuration is incomplete"
            )
        mock_idp = by_name[self.mock_idp_service]["spec"]["template"]["spec"][
            "containers"
        ][0]
        if not any(
            (port.get("containerPort") == 8080 for port in mock_idp.get("ports", []))
        ):
            raise RuntimeError("mock IdP OAuth2-like endpoints are not exposed")
        runtime = self._authguard_runtime_config()
        required = (
            f"base_url: 'http://{self.keycloak_service}",
            f"url: 'ldap://{self.ldap_service}",
            "discovery_id: e2e-authguard-keycloak",
            "discovery_id: e2e-authguard-direct-ldap",
            "${AUTHGUARD__AUTHN__PROVIDERS__E2E_AUTHGUARD_KEYCLOAK__CLIENT_SECRET}",
            "${AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__KEYCLOAK__INDEX_0__AUTH__CLIENT_SECRET}",
            "${AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__LDAP__INDEX_0__AUTH__BIND_PASSWORD}",
            "${AUTHGUARD__AUTHN__PROVIDERS__GITHUB__CLIENT_SECRET}",
            "${AUTHGUARD__AUTHN__PROVIDERS__GOOGLE__CLIENT_SECRET}",
            "${AUTHGUARD__AUTHN__PROVIDERS__WECHAT__CLIENT_SECRET}",
            "${AUTHGUARD__AUTHN__PROVIDERS__QQ__CLIENT_SECRET}",
            "${AUTHGUARD__STORAGE__POSTGRES__PASSWORD}",
            "${AUTHGUARD__AUTHZ__API__TOKEN}",
        )
        if missing := [value for value in required if value not in runtime]:
            raise RuntimeError(
                f"AuthZ discovery runtime configuration is incomplete: {missing}"
            )
        with self._forward_service(self.keycloak_service, 8080) as port:
            with request.urlopen(
                f"http://127.0.0.1:{port}/realms/example-corp/.well-known/openid-configuration",
                timeout=15,
            ) as response:
                metadata = json.loads(response.read())
        if metadata.get("issuer") != self.issuer or not metadata.get("token_endpoint"):
            raise RuntimeError(
                "Keycloak imported realm does not expose the expected OIDC metadata"
            )
        with self._forward_service(self.mock_idp_service, 8080) as port:
            with request.urlopen(
                f"http://127.0.0.1:{port}/healthz", timeout=15
            ) as response:
                mock_health = json.loads(response.read())
        if set(mock_health.get("providers", [])) != {
            "github",
            "google",
            "wechat",
            "qq",
        }:
            raise RuntimeError(
                "mock IdP did not initialize all OAuth2-like provider endpoints"
            )
        self._verify_secret_wiring()
        self.details.append(
            "Keycloak imported the deterministic realm/users/groups/clients; LDAP mounted its bind scenario data; the mock IdP exposed GitHub/Google/WeChat/QQ contracts; AuthZ discovery references enterprise directories through Secret-backed credentials"
        )

    def _verify_secret_wiring(self) -> None:
        """Verify secret keys and references without reading any secret value."""
        template = '{{range $key, $_ := .data}}{{printf "%s\\n" $key}}{{end}}'
        keys = set(
            self._run(
                (
                    "kubectl",
                    "get",
                    "secret",
                    self.principal_discovery_secret,
                    "-n",
                    self.namespace,
                    "-o",
                    f"go-template={template}",
                )
            ).output.splitlines()
        )
        expected = {
            "AUTHGUARD__STORAGE__POSTGRES__PASSWORD",
            "AUTHGUARD__CACHE__REDIS__PASSWORD",
            "AUTHGUARD__AUTHN__PROVIDERS__GITHUB__CLIENT_SECRET",
            "AUTHGUARD__AUTHN__PROVIDERS__GOOGLE__CLIENT_SECRET",
            "AUTHGUARD__AUTHN__PROVIDERS__WECHAT__CLIENT_SECRET",
            "AUTHGUARD__AUTHN__PROVIDERS__QQ__CLIENT_SECRET",
            "AUTHGUARD__AUTHN__PROVIDERS__E2E_AUTHGUARD_KEYCLOAK__CLIENT_SECRET",
            "AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__KEYCLOAK__INDEX_0__AUTH__CLIENT_SECRET",
            "AUTHGUARD__AUTHN__STANDALONE__CREDENTIAL_ENCRYPTION_KEY",
            "AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__LDAP__INDEX_0__AUTH__BIND_PASSWORD",
            "AUTHGUARD__AUTHZ__API__TOKEN",
            "AUTHGUARD__AUTHZ__SCOPE_DELIVERY__DIRECT_CONTEXT_HMAC_KEY",
        }
        if missing := (expected - keys):
            raise RuntimeError(
                f"external integration Secret lacks keys: {sorted(missing)}"
            )
        self.details.append(
            "verified one key-only Secret for PostgreSQL, Redis, GitHub, Google, WeChat, QQ, Keycloak, LDAP, SCIM, standalone encryption, and direct scope signing; no value was read"
        )

    def _wait_for_gateway_api_acceptance(self) -> None:
        deadline = time.monotonic() + self.context.timeout_seconds
        expected_routes = {
            self.workload_service(component) for component in self.workload_images
        }
        expected_routes.add(self.authn_route_name)
        expected_routes.add(self.authguard_web_route)
        last_state = "Gateway API status was not observed"
        while time.monotonic() < deadline:
            resources = json.loads(
                self._run(
                    (
                        "kubectl",
                        "get",
                        "gateway,httproute,securitypolicy",
                        "-n",
                        self.namespace,
                        "-o",
                        "json",
                    )
                ).output
            )["items"]
            gateway_accepted = False
            accepted_routes: set[str] = set()
            policy_accepted = False
            accepted_policy: dict | None = None
            for resource in resources:
                kind = resource["kind"]
                name = resource["metadata"]["name"]
                if kind == "Gateway" and name == self.gateway_name:
                    gateway_accepted = self._has_true_condition(
                        resource.get("status", {}).get("conditions", []), "Accepted"
                    )
                elif kind == "HTTPRoute" and name in expected_routes:
                    parents = resource.get("status", {}).get("parents", [])
                    if any(
                        (
                            self._has_true_condition(
                                parent.get("conditions", []), "Accepted"
                            )
                            for parent in parents
                        )
                    ):
                        accepted_routes.add(name)
                elif kind == "SecurityPolicy" and name == self.authguard_release:
                    ancestors = resource.get("status", {}).get("ancestors", [])
                    policy_accepted = any(
                        (
                            self._has_true_condition(
                                ancestor.get("conditions", []), "Accepted"
                            )
                            for ancestor in ancestors
                        )
                    )
                    accepted_policy = resource
            if (
                gateway_accepted
                and accepted_routes == expected_routes
                and policy_accepted
            ):
                if accepted_policy is None:
                    raise RuntimeError("accepted SecurityPolicy payload is unavailable")
                self._verify_security_policy_contract(accepted_policy)
                self.details.append(
                    "Gateway, five labelled protected business routes, and same-origin public AuthN/UI routes are accepted"
                )
                return
            last_state = f"gateway={gateway_accepted}, routes={len(accepted_routes)}/{len(expected_routes)}, securityPolicy={policy_accepted}"
            time.sleep(1)
        raise RuntimeError(f"Gateway API resources were not accepted: {last_state}")

    @staticmethod
    def _has_true_condition(
        conditions: list[dict[str, object]], condition_type: str
    ) -> bool:
        return any(
            (
                condition.get("type") == condition_type
                and condition.get("status") == "True"
                for condition in conditions
            )
        )

    def _verify_security_policy_contract(self, policy: dict) -> None:
        spec = policy.get("spec", {})
        selectors = spec.get("targetSelectors", [])
        if not any(
            (
                selector.get("group") == "gateway.networking.k8s.io"
                and selector.get("kind") == "HTTPRoute"
                and (
                    selector.get("matchLabels", {}).get("authguard.io/protected")
                    == "true"
                )
                for selector in selectors
            )
        ):
            raise RuntimeError(
                "SecurityPolicy must target explicitly labelled protected HTTPRoutes"
            )
        ext_auth = spec.get("extAuth", {})
        grpc = ext_auth.get("grpc", {})
        backends = grpc.get("backendRefs", [])
        expected_backend = {"name": self.authguard_release, "port": 8080}
        if ext_auth.get("failOpen") is not False:
            raise RuntimeError("SecurityPolicy extAuth must fail closed")
        if not any(
            (
                backend.get("name") == expected_backend["name"]
                and backend.get("port") == expected_backend["port"]
                for backend in backends
            )
        ):
            raise RuntimeError(
                "SecurityPolicy extAuth does not target the Authguard Check gRPC port"
            )
        required_headers = {
            "authorization",
            "cookie",
            "x-request-id",
            "traceparent",
            "tracestate",
        }
        configured_headers = set(ext_auth.get("headersToExtAuth", []))
        if not required_headers.issubset(configured_headers):
            missing = sorted(required_headers - configured_headers)
            raise RuntimeError(
                f"SecurityPolicy does not forward required auth/trace headers to extAuth: missing={missing}"
            )
        providers = spec.get("jwt", {}).get("providers", [])
        issuers = {provider.get("issuer") for provider in providers}
        if issuers != {self.authn_issuer}:
            raise RuntimeError(
                "Envoy JWT policy must trust only the canonical AuthN issuer"
            )
        jwt = spec.get("jwt", {})
        providers = jwt.get("providers", [])
        provider = next(
            (
                candidate
                for candidate in providers
                if candidate.get("issuer") == self.authn_issuer
            ),
            None,
        )
        if jwt.get("optional") is not False or provider is None:
            raise RuntimeError("SecurityPolicy does not require the E2E AuthN issuer")
        if "customer-growth-job-service" not in provider.get("audiences", []):
            raise RuntimeError(
                "SecurityPolicy does not validate the workload JWT audience"
            )
        expected_jwks_config_map = f"{self.keycloak_service}-realm-jwks"
        local_jwks = provider.get("localJWKS", {})
        value_ref = local_jwks.get("valueRef", {})
        if "remoteJWKS" in provider:
            raise RuntimeError("SecurityPolicy unexpectedly loads remote JWKS")
        if (
            local_jwks.get("type") != "ValueRef"
            or value_ref.get("kind") != "ConfigMap"
            or value_ref.get("name") != expected_jwks_config_map
        ):
            raise RuntimeError(
                f"SecurityPolicy does not load the deterministic realm JWKS from the support ConfigMap {expected_jwks_config_map}"
            )
        jwks = json.loads(
            (
                E2EOtherDefinitions.AUTHGUARD_JWT_KEYS_DIR / "realm-signing-jwk.json"
            ).read_text(encoding="utf-8")
        )
        if not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
            raise RuntimeError("the deterministic Envoy local JWKS must contain keys")
        self.details.append(
            "SecurityPolicy requires only the AuthN issuer/audience and deterministic local JWKS, then calls fail-closed Authguard ext_auth gRPC on labelled routes"
        )

    def _verify_redis_cluster(self) -> None:
        result = self._run(
            (
                "kubectl",
                "get",
                "pods",
                "-n",
                self.namespace,
                "-l",
                "app.kubernetes.io/name=redis-cluster",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            )
        )
        pod = result.output.strip()
        cluster = self._run(
            (
                "kubectl",
                "exec",
                "-n",
                self.namespace,
                pod,
                "--",
                "bash",
                "-lc",
                'REDISCLI_AUTH="$REDIS_PASSWORD" /opt/bitnami/redis/bin/redis-cli cluster info',
            )
        )
        if "cluster_state:ok" not in cluster.output:
            raise RuntimeError("Redis Cluster is not healthy")
        self.details.append("Redis Cluster reports all slots covered")

    def _verify_wallet_nodes(self) -> None:
        chain_id = self.infrastructure.json_rpc(self.anvil_service, 8545, "eth_chainId")
        if chain_id != hex(31337):
            raise RuntimeError(f"local Anvil chain id mismatch: {chain_id!r}")
        if self.infrastructure.json_rpc(self.solana_service, 8899, "getHealth") != "ok":
            raise RuntimeError("local Solana validator is not healthy")
        genesis_hash = self.infrastructure.json_rpc(
            self.solana_service, 8899, "getGenesisHash"
        )
        reference = self.infrastructure.solana_chain_reference()
        if not isinstance(genesis_hash, str) or genesis_hash[:32] != reference:
            raise RuntimeError(
                "Solana CAIP-2 reference is not derived from live genesis"
            )
        self.details.append(
            "real local Anvil chain 31337 and Solana validator are healthy; only contract-wallet AuthN receives the Anvil RPC"
        )

    def _verify_running_images(self) -> None:
        result = self._run(
            ("kubectl", "get", "pods", "-n", self.namespace, "-o", "json")
        )
        pod_list = json.loads(result.output)
        images = {
            container["image"]
            for pod in pod_list["items"]
            for container in pod["spec"].get("initContainers", [])
            + pod["spec"].get("containers", [])
            + pod["spec"].get("ephemeralContainers", [])
        }
        expected = {
            *self.images.all_images,
            self.image_references["authguard"],
            self.image_references["web"],
            self.image_references["mock-idp"],
            *self.workload_images.values(),
        }
        missing = expected - images
        if missing:
            raise RuntimeError(
                f"expected runtime images are not running: {sorted(missing)}"
            )
        unexpected = images - expected
        if unexpected:
            raise RuntimeError(f"unexpected runtime images: {sorted(unexpected)}")
        self.details.append(
            f"all dependency images use the {self.images.source} source and AuthGuard uses its configured immutable runtime and Web images"
        )

    def _verify_zero_container_restarts(self) -> None:
        result = self._run(
            ("kubectl", "get", "pods", "-n", self.namespace, "-o", "json")
        )
        restarted: list[str] = []
        for pod in json.loads(result.output)["items"]:
            statuses = pod.get("status", {}).get("initContainerStatuses", []) + pod.get(
                "status", {}
            ).get("containerStatuses", [])
            restart_count = sum((status.get("restartCount", 0) for status in statuses))
            if restart_count:
                restarted.append(f"{pod['metadata']['name']}={restart_count}")
        if restarted:
            raise RuntimeError(
                "containers restarted during clean E2E deployment: "
                + ", ".join(restarted)
            )
        self.details.append("all E2E containers remained at zero restarts")

    @staticmethod
    def create_deployer(context: VerificationContext):
        if context.deployer == "kubernetes":
            return E2ES00InfrastructureVerifier.KubernetesDeployment(context)
        if context.deployer == "docker":
            return E2ES00InfrastructureVerifier.DockerDeployment(context)
        raise ValueError(f"unsupported E2E deployer: {context.deployer}")

    def _verify_iam_schema(self) -> None:
        values = E2EPostgresChecker.check_counts(
            self.infrastructure.postgresql_query,
            {
                "iam_table_count": (
                    "(SELECT count(*) FROM information_schema.tables WHERE table_schema='authguard' AND table_name LIKE 'iam_%')",
                    7,
                    7,
                )
            },
        )
        self.details.append(f"Persisted scenario state: {values}")
