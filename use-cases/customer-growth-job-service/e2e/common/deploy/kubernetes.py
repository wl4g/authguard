"""Disposable Kubernetes deployment lifecycle for the complete E2E suite."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Iterator

from .base import (
    ALIYUN_ANVIL_IMAGE,
    ALIYUN_ENVOY_GATEWAY_IMAGE,
    ALIYUN_ENVOY_IMAGE,
    ALIYUN_JAEGER_IMAGE,
    ALIYUN_KEYCLOAK_IMAGE,
    ALIYUN_LDAP_IMAGE,
    ALIYUN_POSTGRES_IMAGE,
    ALIYUN_REDIS_IMAGE,
    ALIYUN_SOLANA_IMAGE,
    AUTHGUARD_IMAGE,
    AUTHGUARD_WEB_IMAGE,
    AUTHN_BROWSER_HOST,
    AUTHN_HOST,
    BaseE2EDeployer,
    CUSTOMER_GROWTH_FALLBACK_HOST,
    CUSTOMER_GROWTH_HOST,
    MOCK_IDP_IMAGE,
    WORKLOAD_IMAGES,
)
from ..config import CONFIG_DIR, E2E_DIR, PROJECT_ROOT
from ..model import RunContext


E2E_KEYS_DIR = CONFIG_DIR / "e2e-jwt-keys"
KUBERNETES_IMAGE_LOADER_ENV = "AUTHGUARD_E2E_KUBERNETES_IMAGE_LOADER"
KUBERNETES_CLUSTER_ENV = "AUTHGUARD_E2E_KUBERNETES_CLUSTER"


class KubernetesLocalImageLoader:
    """Load locally-built E2E images into the active local Kubernetes cluster."""

    _SUPPORTED = {"auto", "k3s", "kind", "minikube", "k3d", "containerd"}

    def __init__(
        self,
        deployer: "KubernetesE2EDeployer",
        kind: str,
        cluster: str = "",
        ctr_command: tuple[str, ...] = (),
    ) -> None:
        self.deployer = deployer
        self.kind = kind
        self.cluster = cluster
        self.ctr_command = ctr_command

    @classmethod
    def detect(cls, deployer: "KubernetesE2EDeployer") -> "KubernetesLocalImageLoader":
        requested = os.getenv(KUBERNETES_IMAGE_LOADER_ENV, "auto").lower()
        if requested not in cls._SUPPORTED:
            supported = ", ".join(sorted(cls._SUPPORTED))
            raise RuntimeError(
                f"{KUBERNETES_IMAGE_LOADER_ENV} must be one of: {supported}"
            )
        context = deployer._run(("kubectl", "config", "current-context")).output.strip()
        node_version = deployer._run(
            (
                "kubectl",
                "get",
                "nodes",
                "-o",
                "jsonpath={.items[0].status.nodeInfo.kubeletVersion}",
            )
        ).output.strip().lower()
        cluster = os.getenv(KUBERNETES_CLUSTER_ENV, "")
        active_cluster_is_local = cls._active_cluster_is_local(deployer)

        if requested in {"auto", "kind"} and (
            requested == "kind" or context.startswith("kind-")
        ):
            if shutil.which("kind"):
                kind_cluster = cluster or context.removeprefix("kind-")
                if kind_cluster:
                    return cls(deployer, "kind", kind_cluster)
        if requested in {"auto", "minikube"} and (
            requested == "minikube" or context == "minikube"
        ):
            if shutil.which("minikube"):
                return cls(deployer, "minikube", cluster or "minikube")
        if requested in {"auto", "k3d"} and (
            requested == "k3d" or context.startswith("k3d-")
        ):
            if shutil.which("k3d"):
                k3d_cluster = cluster or context.removeprefix("k3d-")
                if k3d_cluster:
                    return cls(deployer, "k3d", k3d_cluster)
        if requested in {"auto", "k3s"} and (
            requested == "k3s" or "k3s" in node_version
        ) and active_cluster_is_local:
            ctr_command = cls._k3s_ctr_command()
            if ctr_command:
                return cls(deployer, "k3s", ctr_command=ctr_command)
        if requested in {"auto", "containerd"} and active_cluster_is_local:
            ctr_command = cls._host_ctr_command(deployer)
            if ctr_command:
                return cls(deployer, "containerd", ctr_command=ctr_command)

        raise RuntimeError(
            "no local Kubernetes image loader was detected for context "
            f"{context!r}; E2E local images require k3s, kind, minikube, k3d, "
            "or host containerd. Select one with "
            f"{KUBERNETES_IMAGE_LOADER_ENV}."
        )

    @staticmethod
    def _active_cluster_is_local(deployer: "KubernetesE2EDeployer") -> bool:
        local_names = {
            socket.gethostname().lower(),
            socket.getfqdn().lower(),
        }
        local_names.update(name.partition(".")[0] for name in tuple(local_names))
        local_ips = set(
            deployer._run(("hostname", "-I"), allowed_codes={0, 1}).output.split()
        )
        nodes = json.loads(deployer._run(("kubectl", "get", "nodes", "-o", "json")).output)
        for node in nodes.get("items", []):
            name = node.get("metadata", {}).get("name", "").lower()
            if name in local_names or name.partition(".")[0] in local_names:
                return True
            addresses = node.get("status", {}).get("addresses", [])
            if any(address.get("address") in local_ips for address in addresses):
                return True
        return False

    @staticmethod
    def _k3s_ctr_command() -> tuple[str, ...]:
        if not shutil.which("k3s"):
            return ()
        if os.geteuid() == 0:
            return ("k3s", "ctr")
        if shutil.which("sudo"):
            return ("sudo", "-n", "k3s", "ctr")
        return ()

    @staticmethod
    def _host_ctr_command(
        deployer: "KubernetesE2EDeployer",
    ) -> tuple[str, ...]:
        if not shutil.which("ctr"):
            return ()
        candidates = [("ctr",)] if os.geteuid() == 0 else [("sudo", "-n", "ctr")]
        for command in candidates:
            result = deployer._run(
                (*command, "-n", "k8s.io", "images", "list", "-q"),
                allowed_codes={0, 1},
            )
            if result.return_code == 0:
                return command
        return ()

    @property
    def description(self) -> str:
        return self.kind if not self.cluster else f"{self.kind}:{self.cluster}"

    def cached_images(self) -> set[str]:
        if self.kind not in {"k3s", "containerd"}:
            return set()
        if not self.ctr_command:
            raise RuntimeError(f"{self.kind} image loader has no ctr command")
        return set(
            self.deployer._run(
                (*self.ctr_command, "-n", "k8s.io", "images", "list", "-q")
            ).output.splitlines()
        )

    def import_image(self, image: str) -> None:
        if self.kind == "kind":
            self.deployer._run(
                ("kind", "load", "docker-image", image, "--name", self.cluster)
            )
            return
        if self.kind == "minikube":
            self.deployer._run(("minikube", "image", "load", image, "-p", self.cluster))
            return
        if self.kind == "k3d":
            self.deployer._run(("k3d", "image", "import", image, "--cluster", self.cluster))
            return
        if self.kind not in {"k3s", "containerd"}:
            raise RuntimeError(f"unsupported Kubernetes image loader: {self.kind}")
        if not self.ctr_command:
            raise RuntimeError(f"{self.kind} image loader has no ctr command")
        exporter = ("docker", "save", image)
        importer = (*self.ctr_command, "-n", "k8s.io", "images", "import", "-")
        self.deployer._run(
            (
                "bash",
                "-o",
                "pipefail",
                "-c",
                f"{shlex.join(exporter)} | {shlex.join(importer)}",
            )
        )

    def remove_image(self, image: str) -> None:
        if self.kind not in {"k3s", "containerd"}:
            return
        if not self.ctr_command:
            raise RuntimeError(f"{self.kind} image loader has no ctr command")
        self.deployer._run(
            (*self.ctr_command, "-n", "k8s.io", "images", "remove", image),
            allowed_codes={0, 1},
        )


class KubernetesE2EDeployer(BaseE2EDeployer):
    """Own one disposable namespace and the three Helm releases inside it."""

    backend = "kubernetes"

    def __init__(self, context: RunContext) -> None:
        super().__init__(context)
        self.namespace = os.getenv(
            "AUTHGUARD_E2E_NAMESPACE", "e2e-authguard-customer-growth"
        )
        self.release = os.getenv(
            "AUTHGUARD_E2E_RELEASE", "e2e-authguard-customer-growth"
        )
        if not self.namespace.startswith("e2e-authguard-"):
            raise ValueError("AUTHGUARD_E2E_NAMESPACE must start with e2e-authguard-")
        if not self.release.startswith("e2e-authguard-"):
            raise ValueError("AUTHGUARD_E2E_RELEASE must start with e2e-authguard-")
        self.envoy_release = f"{self.release}-envoy"
        self.support_release = f"{self.release}-support"
        self.authguard_release = f"{self.release}-authguard"
        self.authguard_authz_service = self.authguard_release
        self.authguard_authn_service = f"{self.authguard_release}-authn"
        self.gateway_name = "e2e-authguard-customer-growth-gateway"
        self.environment = {
            "KUBECONFIG": os.getenv(
                "KUBECONFIG", str(Path.home() / ".kube" / "config")
            )
        }
        self.helm_chart = PROJECT_ROOT / "deploy" / "helm" / "authguard"
        self.support_chart = E2E_DIR / "helm"
        self.deploy_dir = E2E_DIR / "deploy"
        self._image_loader: KubernetesLocalImageLoader | None = None

    @property
    def keycloak_service(self) -> str:
        return f"{self.support_release}-keycloak"

    @property
    def postgresql_service(self) -> str:
        return f"{self.support_release}-postgresql"

    @property
    def jaeger_service(self) -> str:
        return f"{self.support_release}-jaeger"

    @property
    def ldap_service(self) -> str:
        return f"{self.support_release}-ldap"

    @property
    def principal_discovery_secret(self) -> str:
        return f"{self.support_release}-principal-discovery-credentials"[:63].rstrip("-")

    @property
    def mock_idp_service(self) -> str:
        return f"{self.support_release}-mock-idp"

    @property
    def anvil_service(self) -> str:
        return f"{self.support_release}-anvil"

    @property
    def solana_service(self) -> str:
        return f"{self.support_release}-solana"

    @property
    def authguard_web_service(self) -> str:
        return f"{self.authguard_release}-web"

    @property
    def authguard_web_route(self) -> str:
        return "e2e-authguard-customer-growth-web"

    @property
    def gateway_controller_name(self) -> str:
        """Controller identity dedicated to this isolated E2E GatewayClass."""
        return f"e2e.authguard.io/{self.gateway_name}"

    def workload_service(self, component: str) -> str:
        return f"{self.support_release}-{component}"

    @property
    def issuer(self) -> str:
        return (
            f"http://{self.keycloak_service}.{self.namespace}.svc.cluster.local:8080"
            "/realms/example-corp"
        )

    @property
    def authn_issuer(self) -> str:
        return "urn:authguard:e2e:authn"

    @property
    def redis_node(self) -> str:
        return f"redis://e2e-redis-cluster.{self.namespace}.svc.cluster.local:6379"

    @property
    def iam_postgres_url(self) -> str:
        return (
            f"postgresql://{self.internal_hostname(self.postgresql_service)}:5432/"
            "e2e_authguard_customer_growth?sslmode=disable&options=-csearch_path%3Dauthguard"
        )

    def verify_prerequisites(self) -> None:
        self.require_executables("docker", "helm", "kubectl")
        self._run(("kubectl", "version", "--client=true"))
        self._run(("kubectl", "get", "nodes"))
        self._local_image_loader()

    def redeploy(self) -> None:
        self._run(("helm", "dependency", "list", str(self.helm_chart)))
        self._run(("helm", "dependency", "list", str(self.support_chart)))
        if self.context.clean:
            self.cleanup()
        self._run(("kubectl", "create", "namespace", self.namespace), allowed_codes={0, 1})
        if self.context.build_images:
            self._build_images()
        self._prepare_external_images()
        self._install_envoy_gateway()
        self._remove_mutable_cluster_images()
        # Workload Pods deliberately use imagePullPolicy: Never. Import every
        # mutable local image before their Helm release creates a consumer so a
        # kubelet never records an ErrImageNeverPull before that tag exists.
        self._prepare_workload_images()
        self._install_support_services()
        # Support Pods now reference their immutable images. Re-check after the
        # mutable imports so a local cluster image cache cannot lose a large,
        # previously idle chain image before Pod startup.
        self._prepare_external_images()
        self._wait_for_support_services()
        self._import_image(AUTHGUARD_IMAGE)
        # The Web Pod is created by the AuthGuard chart, not the support chart.
        # Re-import immediately before Helm creates that consumer so a local
        # cluster image cache cannot collect it during support startup.
        self._import_image(AUTHGUARD_WEB_IMAGE)
        # Import Redis immediately before Helm creates the StatefulSet. The chart
        # still uses IfNotPresent so kubelet can recover from image GC by pulling
        # the same immutable Aliyun tag in constrained CI environments.
        self._import_image(ALIYUN_REDIS_IMAGE)
        self._install_authguard()
        self._wait_for_resources()

    def cleanup(self) -> None:
        """Remove every namespaced E2E Helm release and its isolated namespace."""
        for release in (
            self.authguard_release,
            self.support_release,
            self.envoy_release,
        ):
            self._run(
                (
                    "helm",
                    "uninstall",
                    release,
                    "-n",
                    self.namespace,
                    "--wait",
                    "--timeout=90s",
                ),
                allowed_codes={0, 1},
            )
        self._run(
            (
                "kubectl",
                "delete",
                "namespace",
                self.namespace,
                "--ignore-not-found=true",
                "--wait=false",
            )
        )
        deadline = time.monotonic() + self.context.timeout_seconds
        while time.monotonic() < deadline:
            existing = self._run(
                ("kubectl", "get", "namespace", self.namespace, "-o", "name"),
                allowed_codes={0, 1},
            )
            if existing.return_code != 0:
                return
            time.sleep(1)
        raise RuntimeError(f"timed out deleting namespace {self.namespace}")

    def _prepare_external_images(self) -> None:
        external_images = (
            ALIYUN_ENVOY_IMAGE,
            ALIYUN_ENVOY_GATEWAY_IMAGE,
            ALIYUN_REDIS_IMAGE,
            ALIYUN_KEYCLOAK_IMAGE,
            ALIYUN_LDAP_IMAGE,
            ALIYUN_JAEGER_IMAGE,
            ALIYUN_POSTGRES_IMAGE,
            ALIYUN_ANVIL_IMAGE,
            ALIYUN_SOLANA_IMAGE,
        )
        loader = self._local_image_loader()
        cluster_images = loader.cached_images()
        for image in external_images:
            if image in cluster_images:
                self.details.append(f"reuse {loader.description} image: {image}")
                continue
            inspected = self._run(
                # Docker returns 1 for a missing image; the Podman-compatible
                # Docker CLI returns 125 for the same non-fatal cache miss.
                ("docker", "image", "inspect", image), allowed_codes={0, 1, 125}
            )
            if inspected.return_code != 0:
                self._run(("docker", "pull", image))
            self._import_image(image)

    def _prepare_workload_images(self) -> None:
        # e2e-local tags are intentionally mutable. Import them immediately before
        # creating their Pods so a local cluster image cache cannot collect an
        # unreferenced image while an earlier Helm release becomes ready.
        for image in (
            *WORKLOAD_IMAGES.values(),
            MOCK_IDP_IMAGE,
            AUTHGUARD_WEB_IMAGE,
        ):
            self._import_image(image)

    def _remove_mutable_cluster_images(self) -> None:
        """Prevent a recreated Pod from starting an obsolete mutable E2E image tag."""
        loader = self._local_image_loader()
        for image in (
            *WORKLOAD_IMAGES.values(),
            MOCK_IDP_IMAGE,
            AUTHGUARD_WEB_IMAGE,
        ):
            loader.remove_image(image)

    def _import_image(self, image: str) -> None:
        loader = self._local_image_loader()
        inspected = self._run(
            ("docker", "image", "inspect", image), allowed_codes={0, 1, 125}
        )
        if inspected.return_code != 0:
            cluster_images = loader.cached_images()
            if image in cluster_images:
                self.details.append(f"reuse {loader.description} image: {image}")
                return
            if image.endswith(":e2e-local"):
                raise RuntimeError(
                    "image is unavailable from both the local builder and "
                    f"{loader.description}: {image}"
                )
            # A local cluster cache can lose an unreferenced dependency between
            # the initial cache check and a later Helm install. Immutable images
            # are safe to re-pull; mutable E2E images fail closed above.
            self._run(("docker", "pull", image))
        loader.import_image(image)

    def _install_envoy_gateway(self) -> None:
        chart_archives = sorted((self.helm_chart / "charts").glob("gateway-helm-*.tgz"))
        if not chart_archives:
            raise RuntimeError("Envoy Gateway dependency archive was not built")
        self._run(
            (
                "helm",
                "upgrade",
                "--install",
                self.envoy_release,
                str(chart_archives[-1]),
                "-n",
                self.namespace,
                "--set",
                f"global.images.envoyGateway.image={ALIYUN_ENVOY_GATEWAY_IMAGE}",
                "--set",
                "global.images.envoyGateway.pullPolicy=Never",
                "--set",
                f"global.images.envoyProxy.image={ALIYUN_ENVOY_IMAGE}",
                "--set",
                "global.images.envoyProxy.pullPolicy=Never",
                "--set-string",
                f"config.envoyGateway.gateway.controllerName={self.gateway_controller_name}",
                "--wait",
                f"--timeout={self.context.timeout_seconds}s",
            )
        )

    def _install_support_services(self) -> None:
        grpc_target = f"{self.authguard_release}.{self.namespace}.svc.cluster.local:8081"
        self._run(
            (
                "helm",
                "upgrade",
                "--install",
                self.support_release,
                str(self.support_chart),
                "-n",
                self.namespace,
                "--set-file",
                f"keycloak.realm={CONFIG_DIR / 'keycloak-realm.json'}",
                "--set-file",
                f"supportPostgresql.initSQL={CONFIG_DIR / 'init.sql'}",
                "--set-file",
                f"keycloak.realmSigningPrivateKey={E2E_KEYS_DIR / 'realm-signing-key.pem'}",
                "--set-file",
                f"keycloak.realmSigningCertificate={E2E_KEYS_DIR / 'realm-signing-cert.pem'}",
                "--set-file",
                f"keycloak.realmSigningJwks={E2E_KEYS_DIR / 'realm-signing-jwk.json'}",
                "--set-file",
                f"keycloak.resignJwtPrivateKey={E2E_KEYS_DIR / 'resign-jwt-key.pem'}",
                "--set-file",
                f"keycloak.resignJwtPublicKey={E2E_KEYS_DIR / 'resign-jwt-key.pub.pem'}",
                "--set",
                f"authguard-middleware.grpcTarget={grpc_target}",
                "--set",
                f"gateway.name={self.gateway_name}",
            )
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
            *[self.workload_service(component) for component in WORKLOAD_IMAGES],
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
        # Install the optional vendored subchart from the same business Chart,
        # but under a distinct release. Normal business upgrades use the
        # default authguard-middleware.enabled=false and cannot mutate it.
        authguard_values = self._authguard_values()
        authguard_values["enabled"] = True
        values = {
            "support": {"enabled": False},
            "authguard-middleware": authguard_values,
            "global": {
                "authguard": {
                    "themeRevision": "v1",
                    "themeConfigMap": (
                        "{{ .Release.Name }}-authguard-theme-"
                        "{{ .Values.global.authguard.themeRevision }}"
                    ),
                }
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as values_file:
            json.dump(values, values_file)
            values_file.flush()
            self._run(
                (
                    "helm",
                    "upgrade",
                    "--install",
                    self.authguard_release,
                    str(self.support_chart),
                    "-n",
                    self.namespace,
                    "-f",
                    values_file.name,
                    "--wait",
                    f"--timeout={self.context.timeout_seconds}s",
                )
            )

    def _authguard_values(self) -> dict:
        authguard_config = self._authguard_runtime_config()
        return {
            "envoy_gateway": {
                "enabled": False,
                "nameOverride": "envoy-gateway",
                "global": {
                    "images": {
                        "envoyProxy": {
                            "image": ALIYUN_ENVOY_IMAGE,
                            "pullPolicy": "Never",
                        }
                    }
                },
                "ext_authz": {
                    "enabled": True,
                    "gateway": {
                        "create": True,
                        "className": self.gateway_name,
                        "name": self.gateway_name,
                        "listenerPort": 8082,
                        "controllerName": self.gateway_controller_name,
                    },
                    "authguardRoute": {"enabled": False},
                    "authnRoute": {
                        "enabled": True,
                        "name": "e2e-authguard-customer-growth-authn",
                        "hostnames": [
                            AUTHN_HOST,
                            AUTHN_BROWSER_HOST,
                            CUSTOMER_GROWTH_HOST,
                            CUSTOMER_GROWTH_FALLBACK_HOST,
                        ],
                    },
                    "tracing": {
                        "enabled": True,
                        "backendRef": {"name": self.jaeger_service, "port": 4317},
                        "serviceName": "e2e-authguard-envoy-proxy",
                    },
                },
            },
            "redis_cluster": {
                "enabled": True,
                # Keep the StatefulSet controller-revision label below the
                # Kubernetes 63-character limit even when the E2E release
                # name is intentionally descriptive.
                "fullnameOverride": "e2e-redis-cluster",
                "image": {
                    "registry": "registry.cn-shenzhen.aliyuncs.com",
                    "repository": "wl4g-k8s/bitnami_redis-cluster",
                    "tag": "7.0.14",
                    "pullPolicy": "IfNotPresent",
                },
                "existingSecret": self.principal_discovery_secret,
                "existingSecretPasswordKey": "AUTHGUARD__CACHE__REDIS__PASSWORD",
                "cluster": {"nodes": 6, "replicas": 1},
                "persistence": {"enabled": False},
            },
            # The E2E support chart owns its dedicated PostgreSQL instance.
            "postgresql": {"enabled": False},
            "fullnameOverride": self.authguard_release,
            "secrets": {
                # kubernetes provider: the support-chart Secret is injected
                # with envFrom, so all six credentials resolve natively.
                "provider": "kubernetes",
                "kubernetes": {"existingSecret": self.principal_discovery_secret},
            },
            "authguard": {
                "authn": {
                    "enabled": True,
                    "replicaCount": 1,
                    # Four concurrent Argon2id registrations are an intentional
                    # security/concurrency assertion, not a lightweight smoke test.
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                        "limits": {"cpu": "1000m", "memory": "768Mi"},
                    },
                    "image": {
                        "repository": AUTHGUARD_IMAGE.rsplit(":", 1)[0],
                        "tag": AUTHGUARD_IMAGE.rsplit(":", 1)[1],
                        "pullPolicy": "Never",
                    },
                    "disruptionBudget": {"enabled": False},
                    "canonical_jwt": {
                        "issuer": self.authn_issuer,
                        "audiences": ["customer-growth-job-service"],
                        "local_jwks": {
                            "existing_config_map": (
                                f"{self.support_release}-keycloak-realm-jwks"
                            ),
                            "inline": "",
                        },
                        "remote_jwks": {"uri": "", "backend_refs": []},
                    },
                },
                "web": {
                    "enabled": True,
                    "replicaCount": 1,
                    "image": {
                        "repository": AUTHGUARD_WEB_IMAGE.rsplit(":", 1)[0],
                        "tag": AUTHGUARD_WEB_IMAGE.rsplit(":", 1)[1],
                        "pullPolicy": "Never",
                    },
                    "route": {
                        "enabled": True,
                        "name": self.authguard_web_route,
                        "hostnames": [
                            AUTHN_HOST,
                            AUTHN_BROWSER_HOST,
                            CUSTOMER_GROWTH_HOST,
                            CUSTOMER_GROWTH_FALLBACK_HOST,
                        ],
                        "dashboard": {
                            "enabled": True,
                            "name": f"{self.authguard_web_route}-dashboard",
                            "hostnames": [AUTHN_HOST, AUTHN_BROWSER_HOST],
                        },
                    },
                },
                "authz": {
                    "replicaCount": 1,
                    "image": {
                        "repository": AUTHGUARD_IMAGE.rsplit(":", 1)[0],
                        "tag": AUTHGUARD_IMAGE.rsplit(":", 1)[1],
                        "pullPolicy": "Never",
                    },
                    "disruptionBudget": {"enabled": False},
                    "api": {"enabled": True},
                },
                "mgmt": {
                    "enabled": True,
                    "otelEnabled": True,
                    "otelEndpoint": (
                        f"http://{self.jaeger_service}.{self.namespace}"
                        ".svc.cluster.local:4317"
                    ),
                },
                # The complete main configuration is
                # rendered by Helm tpl into the authguard ConfigMap. Policy
                # data is deliberately absent: authorization policies are
                # imported into the Authguard storage as the post-deploy
                # bootstrap step (_bootstrap_authorization_policy).
                "authguard-config": authguard_config,
            },
        }

    def _wait_for_resources(self) -> None:
        for deployment in (
            "envoy-gateway",
            self.keycloak_service,
            self.ldap_service,
            self.jaeger_service,
            self.postgresql_service,
            self.mock_idp_service,
            self.anvil_service,
            self.solana_service,
            *[self.workload_service(component) for component in WORKLOAD_IMAGES],
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
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in item.get("status", {}).get("conditions", [])
            )
        ]
        if not ready:
            raise RuntimeError("no ready Envoy Proxy pod was created")
        pod = max(
            ready,
            key=lambda item: item.get("metadata", {}).get("creationTimestamp", ""),
        ).get("metadata", {}).get("name", "")
        if not pod:
            raise RuntimeError("ready Envoy Proxy pod has no name")
        with self._forward_resource(f"pod/{pod}", 19000) as port:
            yield port

    @contextmanager
    def _forward_service(self, service: str, remote_port: int) -> Iterator[int]:
        with self._forward_resource(f"service/{service}", remote_port) as port:
            yield port

    @contextmanager
    def _forward_resource(self, resource: str, remote_port: int) -> Iterator[int]:
        process: subprocess.Popen | None = None
        forwarded_port = 0
        failures: list[str] = []
        for attempt in range(1, 4):
            forwarded_port = self.free_port()
            process = subprocess.Popen(
                (
                    "kubectl",
                    "port-forward",
                    "--address=127.0.0.1",
                    "-n",
                    self.namespace,
                    resource,
                    f"{forwarded_port}:{remote_port}",
                ),
                cwd=PROJECT_ROOT,
                env={**os.environ, **self.environment},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self._wait_for_port(process, forwarded_port)
                break
            except RuntimeError as error:
                process.terminate()
                stderr = process.communicate(timeout=5)[1].strip()
                failures.append(f"attempt {attempt}: {error}; {stderr or 'no stderr'}")
                process = None
                time.sleep(0.2)
        if process is None:
            raise RuntimeError(
                f"kubectl port-forward {resource}:{remote_port} failed after 3 attempts: "
                + " | ".join(failures)
            )
        try:
            yield forwarded_port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def _local_image_loader(self) -> KubernetesLocalImageLoader:
        if self._image_loader is None:
            self._image_loader = KubernetesLocalImageLoader.detect(self)
            self.details.append(
                f"local Kubernetes image loader: {self._image_loader.description}"
            )
        return self._image_loader

    def service_logs(self, service: str, tail: int = 5000) -> str:
        """Return logs from Pods actually owned by the named Deployment.

        ``kubectl logs deployment/<name>`` uses the Deployment selector.  The
        AuthGuard chart intentionally shares its release labels across AuthN,
        AuthZ, and Web, so that selector can resolve to a sibling Pod.  Follow
        the Deployment -> ReplicaSet -> Pod ownership chain instead; it is
        unambiguous and remains valid if chart labels evolve.
        """
        pod_names = self._deployment_pods(service)
        if not pod_names:
            raise RuntimeError(
                f"deployment {service!r} has no running Pods in namespace "
                f"{self.namespace!r}"
            )
        return "\n".join(
            self._run(
                (
                    "kubectl",
                    "logs",
                    "-n",
                    self.namespace,
                    f"pod/{pod_name}",
                    f"--tail={tail}",
                )
            ).output
            for pod_name in pod_names
        )

    def _deployment_pods(self, deployment: str) -> tuple[str, ...]:
        """Resolve running Pods through the exact Deployment owner chain."""
        replica_sets = json.loads(
            self._run(
                (
                    "kubectl",
                    "get",
                    "replicasets",
                    "-n",
                    self.namespace,
                    "-o",
                    "json",
                )
            ).output
        )
        replica_set_names = {
            item.get("metadata", {}).get("name", "")
            for item in replica_sets.get("items", [])
            if any(
                owner.get("kind") == "Deployment"
                and owner.get("name") == deployment
                for owner in item.get("metadata", {}).get("ownerReferences", [])
            )
        }
        if not replica_set_names:
            return ()

        pods = json.loads(
            self._run(
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    self.namespace,
                    "-o",
                    "json",
                )
            ).output
        )
        return tuple(
            sorted(
                item.get("metadata", {}).get("name", "")
                for item in pods.get("items", [])
                if item.get("status", {}).get("phase") == "Running"
                and any(
                    owner.get("kind") == "ReplicaSet"
                    and owner.get("name") in replica_set_names
                    for owner in item.get("metadata", {}).get("ownerReferences", [])
                )
            )
        )

    def postgresql_query(self, sql: str) -> str:
        pod = self._run(
            (
                "kubectl",
                "get",
                "pods",
                "-n",
                self.namespace,
                "-l",
                "app.kubernetes.io/component=e2e-authguard-postgresql",
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
                "bash",
                "-ec",
                'PGPASSWORD="$POSTGRESQL_POSTGRES_PASSWORD" '
                'PGOPTIONS="-c search_path=authguard" psql '
                '-U postgres -d "$POSTGRESQL_DATABASE" -At '
                '--set=ON_ERROR_STOP=1 --command "$1"',
                "e2e-authguard-query",
                sql,
            )
        ).output.strip()

    def internal_hostname(self, service: str) -> str:
        return f"{service}.{self.namespace}.svc.cluster.local"

    @staticmethod
    def _wait_for_port(process: subprocess.Popen, port: int) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("kubectl port-forward exited before becoming ready")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("timed out waiting for kubectl port-forward")
