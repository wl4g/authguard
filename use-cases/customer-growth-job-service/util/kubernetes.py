"""Disposable Kubernetes deployment lifecycle for the complete E2E suite."""
from __future__ import annotations
from util.process import E2EProcessHelper
from contextlib import contextmanager
import json
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from verifier.context import VerificationContext


class E2EKubernetesDeployer(E2EProcessHelper.Deployment):
    """Own one disposable namespace and component-scoped Helm releases."""

    PLATFORM_ENV = "E2E_PLATFORM"
    local_images = ()

    class _LocalImageLoader:
        """Load locally-built E2E images into the active local Kubernetes cluster."""

        _SUPPORTED = {
            "auto",
            "colima",
            "orbstack",
            "docker",
            "k3s",
            "kind",
            "minikube",
            "k3d",
            "containerd",
        }

        def __init__(
            self,
            deployer: "E2EKubernetesDeployer",
            kind: str,
            cluster: str = "",
            ctr_command: tuple[str, ...] = (),
            platform: str = "",
        ) -> None:
            self.deployer = deployer
            self.kind = kind
            self.cluster = cluster
            self.ctr_command = ctr_command
            self.node_platform = platform
            self.platform = os.getenv(deployer.PLATFORM_ENV, platform)
            allowed = {platform}
            if platform == "linux/arm64":
                allowed.add("linux/amd64")
            if self.platform not in allowed:
                raise RuntimeError(
                    f"unsupported E2E platform {self.platform!r} for node {platform}"
                )
            if platform:
                deployer.environment["DOCKER_DEFAULT_PLATFORM"] = self.platform

        @classmethod
        def detect(
            cls, deployer: "E2EKubernetesDeployer"
        ) -> "E2EKubernetesDeployer._LocalImageLoader":
            requested = os.getenv(deployer.IMAGE_LOADER_ENV, "auto").lower()
            if requested not in cls._SUPPORTED:
                supported = ", ".join(sorted(cls._SUPPORTED))
                raise RuntimeError(
                    f"{deployer.IMAGE_LOADER_ENV} must be one of: {supported}"
                )
            context = deployer._run(
                ("kubectl", "config", "current-context")
            ).output.strip()
            nodes = json.loads(
                deployer._run(("kubectl", "get", "nodes", "-o", "json")).output
            )
            node_info = [node["status"]["nodeInfo"] for node in nodes.get("items", [])]
            architectures = {node["architecture"] for node in node_info}
            if len(architectures) != 1 or not architectures <= {"amd64", "arm64"}:
                raise RuntimeError(
                    f"E2E requires homogeneous amd64 or arm64 nodes: {architectures}"
                )
            platform = f"linux/{next(iter(architectures))}"
            node_version = node_info[0]["kubeletVersion"].lower()
            runtime = node_info[0]["containerRuntimeVersion"]
            cluster = os.getenv(deployer.CLUSTER_ENV, "")
            if context == "orbstack":
                if requested not in {"auto", "orbstack"}:
                    raise RuntimeError(
                        "the active OrbStack context requires the orbstack image loader"
                    )
                deployer.environment["DOCKER_CONTEXT"] = "orbstack"
                deployer._run(("docker", "info", "--format", "{{.ID}}"))
                return cls(deployer, "docker", "orbstack", platform=platform)
            if context == "colima" or context.startswith("colima-"):
                if requested not in {"auto", "colima"}:
                    raise RuntimeError(
                        "the active Colima context requires the colima image loader"
                    )
                if not shutil.which("colima"):
                    raise RuntimeError(
                        "the active Colima context requires the colima CLI"
                    )
                profile = (
                    context.removeprefix("colima-")
                    if context != "colima"
                    else "default"
                )
                vm = ("colima", "-p", profile, "ssh", "--", "sudo", "-n")
                if runtime.startswith("docker://"):
                    deployer.environment["DOCKER_CONTEXT"] = context
                    host_id = deployer._run(
                        ("docker", "info", "--format", "{{.ID}}")
                    ).output.strip()
                    vm_id = deployer._run(
                        (*vm, "docker", "info", "--format", "{{.ID}}")
                    ).output.strip()
                    if not host_id or host_id != vm_id:
                        raise RuntimeError(
                            f"Docker context {context!r} does not share the Colima VM image store"
                        )
                    return cls(deployer, "docker", context, platform=platform)
                if runtime.startswith("containerd://"):
                    for command in ((*vm, "k3s", "ctr"), (*vm, "ctr")):
                        probe = deployer._run(
                            (*command, "-n", "k8s.io", "images", "list", "-q"),
                            allowed_codes={0, 1, 127},
                        )
                        if probe.return_code == 0:
                            return cls(
                                deployer, "containerd", context, command, platform
                            )
                raise RuntimeError(
                    f"unsupported or inaccessible Colima runtime: {runtime}"
                )
            if requested in {"colima", "orbstack"}:
                raise RuntimeError(
                    f"the active Kubernetes context is not {requested}: {context!r}"
                )
            if requested in {"auto", "kind"} and (
                requested == "kind" or context.startswith("kind-")
            ):
                if shutil.which("kind"):
                    kind_cluster = cluster or context.removeprefix("kind-")
                    if kind_cluster:
                        return cls(deployer, "kind", kind_cluster, platform=platform)
            if requested in {"auto", "minikube"} and (
                requested == "minikube" or context == "minikube"
            ):
                if shutil.which("minikube"):
                    return cls(
                        deployer, "minikube", cluster or "minikube", platform=platform
                    )
            if requested in {"auto", "k3d"} and (
                requested == "k3d" or context.startswith("k3d-")
            ):
                if shutil.which("k3d"):
                    k3d_cluster = cluster or context.removeprefix("k3d-")
                    if k3d_cluster:
                        return cls(deployer, "k3d", k3d_cluster, platform=platform)
            active_cluster_is_local = cls._active_cluster_is_local(deployer, nodes)
            if (
                requested in {"auto", "docker", "k3s"}
                and runtime.startswith("docker://")
                and active_cluster_is_local
            ):
                daemon_name = deployer._run(
                    ("docker", "info", "--format", "{{.Name}}")
                ).output.strip()
                node_names = {
                    node["metadata"]["name"].lower() for node in nodes["items"]
                }
                node_names.update(
                    (name.partition(".")[0] for name in tuple(node_names))
                )
                if daemon_name.lower() not in node_names:
                    raise RuntimeError(
                        "Docker daemon does not belong to the active local Kubernetes node"
                    )
                return cls(deployer, "docker", platform=platform)
            if (
                requested in {"auto", "k3s"}
                and (requested == "k3s" or "k3s" in node_version)
                and active_cluster_is_local
            ):
                ctr_command = cls._k3s_ctr_command()
                if ctr_command:
                    return cls(
                        deployer, "k3s", ctr_command=ctr_command, platform=platform
                    )
            if requested in {"auto", "containerd"} and active_cluster_is_local:
                ctr_command = cls._host_ctr_command(deployer)
                if ctr_command:
                    return cls(
                        deployer,
                        "containerd",
                        ctr_command=ctr_command,
                        platform=platform,
                    )
            raise RuntimeError(
                f"no local Kubernetes image loader was detected for context {context!r}; E2E local images require Colima, OrbStack, local Docker, k3s, kind, minikube, k3d, or host containerd. Select one with {deployer.IMAGE_LOADER_ENV}."
            )

        @staticmethod
        def _active_cluster_is_local(
            deployer: "E2EKubernetesDeployer", nodes: dict
        ) -> bool:
            local_names = {socket.gethostname().lower(), socket.getfqdn().lower()}
            local_names.update((name.partition(".")[0] for name in tuple(local_names)))
            local_ips = set(
                deployer._run(("hostname", "-I"), allowed_codes={0, 1}).output.split()
            )
            for node in nodes.get("items", []):
                name = node.get("metadata", {}).get("name", "").lower()
                if name in local_names or name.partition(".")[0] in local_names:
                    return True
                addresses = node.get("status", {}).get("addresses", [])
                if any((address.get("address") in local_ips for address in addresses)):
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
        def _host_ctr_command(deployer: "E2EKubernetesDeployer") -> tuple[str, ...]:
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
            if self.kind == "docker":
                return set(
                    self.deployer._run(
                        (
                            "docker",
                            "image",
                            "ls",
                            "--format",
                            "{{.Repository}}:{{.Tag}}",
                        )
                    ).output.splitlines()
                )
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
            self.validate_image(image)
            if self.kind == "docker":
                return
            if self.kind == "kind":
                self.deployer._run(
                    ("kind", "load", "docker-image", image, "--name", self.cluster)
                )
                return
            if self.kind == "minikube":
                self.deployer._run(
                    ("minikube", "image", "load", image, "-p", self.cluster)
                )
                return
            if self.kind == "k3d":
                self.deployer._run(
                    ("k3d", "image", "import", image, "--cluster", self.cluster)
                )
                return
            if self.kind not in {"k3s", "containerd"}:
                raise RuntimeError(f"unsupported Kubernetes image loader: {self.kind}")
            if not self.ctr_command:
                raise RuntimeError(f"{self.kind} image loader has no ctr command")
            exporter = ("docker", "save", image)
            importer = (
                *self.ctr_command,
                "-n",
                "k8s.io",
                "images",
                "import",
                "--platform",
                self.platform,
                "-",
            )
            self.deployer._run(
                (
                    "bash",
                    "-o",
                    "pipefail",
                    "-c",
                    f"{shlex.join(exporter)} | {shlex.join(importer)}",
                )
            )

        def validate_image(self, image: str) -> None:
            actual = self.deployer._run(
                (
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{.Os}}/{{.Architecture}}",
                    image,
                )
            ).output.strip()
            if actual != self.platform:
                raise RuntimeError(
                    f"image {image} is {actual}, but the selected E2E platform is {self.platform}; pull/build that platform, or explicitly select linux/amd64 on an emulation-enabled VM"
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

    IMAGE_LOADER_ENV = "E2E_KUBERNETES_IMAGE_LOADER"
    CLUSTER_ENV = "E2E_KUBERNETES_CLUSTER"
    backend = "kubernetes"

    @staticmethod
    def _resolve_kubeconfig() -> str:
        """Use the caller's kubeconfig/context; CI supplies its K3s config explicitly."""
        if configured := os.getenv("KUBECONFIG"):
            return configured
        user_config = Path.home() / ".kube" / "config"
        if E2EKubernetesDeployer._has_current_context(user_config):
            return str(user_config)
        raise RuntimeError(
            "no usable Kubernetes context: set KUBECONFIG or configure ~/.kube/config"
        )

    @staticmethod
    def _has_current_context(kubeconfig: Path) -> bool:
        if not kubeconfig.is_file():
            return False
        result = subprocess.run(
            ("kubectl", "--kubeconfig", str(kubeconfig), "config", "current-context"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
        return result.returncode == 0

    def kubectl(self, *arguments: str, allowed_codes: set[int] | None = None):
        return self._run(("kubectl", *arguments), allowed_codes=allowed_codes)

    def resource(
        self, kind: str, name: str = "", *, namespace: str | None = None
    ) -> dict:
        arguments = (
            "get",
            kind,
            *((name,) if name else ()),
            "-n",
            namespace or self.namespace,
            "-o",
            "json",
        )
        return json.loads(self.kubectl(*arguments).output)

    def verify_prerequisites(self) -> None:
        self.require_executables("docker", "helm", "kubectl")
        self._run(("kubectl", "version", "--client=true"))
        self._run(("kubectl", "get", "nodes"))
        self._local_image_loader()

    def _ensure_local_image(self, image: str) -> None:
        loader = self._local_image_loader()
        inspected = self._run(
            (
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Os}}/{{.Architecture}}",
                image,
            ),
            allowed_codes={0, 1, 125},
        )
        if inspected.return_code != 0 or inspected.output.strip() != loader.platform:
            self._pull_image(image)

    def _import_image(self, image: str) -> None:
        loader = self._local_image_loader()
        inspected = self._run(
            (
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Os}}/{{.Architecture}}",
                image,
            ),
            allowed_codes={0, 1, 125},
        )
        if inspected.return_code != 0 or inspected.output.strip() != loader.platform:
            cluster_images = loader.cached_images()
            if (
                inspected.return_code != 0
                and loader.kind != "docker"
                and (image in cluster_images)
            ):
                self.details.append(f"reuse {loader.description} image: {image}")
                return
            if image in self.local_images:
                raise RuntimeError(
                    f"image is unavailable from both the local builder and {loader.description}: {image}"
                )
            self._pull_image(image)
        loader.import_image(image)

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
                cwd=self.project_root,
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

    def _local_image_loader(self) -> E2EKubernetesDeployer._LocalImageLoader:
        if self._image_loader is None:
            self._image_loader = E2EKubernetesDeployer._LocalImageLoader.detect(self)
            self.details.append(
                f"local Kubernetes image loader: {self._image_loader.description}"
            )
        return self._image_loader

    def service_logs(self, service: str, tail: int = 5000) -> str:
        """Return logs from Pods actually owned by the named Deployment.

        ``kubectl logs deployment/<name>`` uses the Deployment selector.  The
        Different Deployments can share chart labels, so that selector can
        resolve to a sibling Pod. Follow
        the Deployment -> ReplicaSet -> Pod ownership chain instead; it is
        unambiguous and remains valid if chart labels evolve.
        """
        pod_names = self._deployment_pods(service)
        if not pod_names:
            raise RuntimeError(
                f"deployment {service!r} has no running Pods in namespace {self.namespace!r}"
            )
        return "\n".join(
            (
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
        )

    def _deployment_pods(self, deployment: str) -> tuple[str, ...]:
        """Resolve running Pods through the exact Deployment owner chain."""
        replica_sets = json.loads(
            self._run(
                ("kubectl", "get", "replicasets", "-n", self.namespace, "-o", "json")
            ).output
        )
        replica_set_names = {
            item.get("metadata", {}).get("name", "")
            for item in replica_sets.get("items", [])
            if any(
                (
                    owner.get("kind") == "Deployment"
                    and owner.get("name") == deployment
                    for owner in item.get("metadata", {}).get("ownerReferences", [])
                )
            )
        }
        if not replica_set_names:
            return ()
        pods = json.loads(
            self._run(
                ("kubectl", "get", "pods", "-n", self.namespace, "-o", "json")
            ).output
        )
        return tuple(
            sorted(
                (
                    item.get("metadata", {}).get("name", "")
                    for item in pods.get("items", [])
                    if item.get("status", {}).get("phase") == "Running"
                    and any(
                        (
                            owner.get("kind") == "ReplicaSet"
                            and owner.get("name") in replica_set_names
                            for owner in item.get("metadata", {}).get(
                                "ownerReferences", []
                            )
                        )
                    )
                )
            )
        )

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

    def cleanup(self) -> None:
        E2EKubernetesCleaner(self).cleanup()

    def __init__(
        self,
        context: VerificationContext,
        *,
        namespace: str = "",
        releases: tuple[str, ...] = (),
    ) -> None:
        super().__init__(context)
        self.namespace = namespace
        self.releases = releases
        self.environment["KUBECONFIG"] = self._resolve_kubeconfig()
        self._image_loader = None

    def redeploy(self) -> None:
        raise NotImplementedError(
            "the infrastructure scenario supplies the deployment plan"
        )

    def helm_install(
        self, release: str, chart: Path, values: dict, *options: str
    ) -> None:
        """Install one component with values resolved from the case image matrix."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as payload:
            json.dump(values, payload)
            payload.flush()
            self._run(
                (
                    "helm",
                    "upgrade",
                    "--install",
                    release,
                    str(chart),
                    "-n",
                    self.namespace,
                    "-f",
                    payload.name,
                    *options,
                )
            )

    def exec(self, resource: str, *command: str):
        return self.kubectl("exec", "-n", self.namespace, resource, "--", *command)


class E2EKubernetesCleaner:
    """Remove only resources owned by the supplied E2E deployment."""

    def __init__(self, deployer: E2EKubernetesDeployer) -> None:
        self.deployer = deployer

    def __getattr__(self, name):
        return getattr(self.deployer, name)

    def cleanup(self) -> None:
        """Remove the E2E namespace, force-finalizing it only when normal GC stalls."""
        for release in self.releases:
            self._run(
                (
                    "helm",
                    "uninstall",
                    release,
                    "-n",
                    self.namespace,
                    "--wait",
                    "--timeout=30s",
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
        deadline = time.monotonic() + min(self.context.timeout_seconds, 90)
        while time.monotonic() < deadline:
            existing = self._run(
                ("kubectl", "get", "namespace", self.namespace, "-o", "name"),
                allowed_codes={0, 1},
            )
            if existing.return_code != 0:
                return
            time.sleep(1)
        self._force_finalize_namespace()

    def _force_finalize_namespace(self) -> None:
        """Use Kubernetes' finalize endpoint only for this stalled E2E namespace."""
        namespace = json.loads(
            self._run(
                ("kubectl", "get", "namespace", self.namespace, "-o", "json")
            ).output
        )
        namespace.setdefault("spec", {})["finalizers"] = []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as payload_file:
            json.dump(namespace, payload_file)
            payload_file.flush()
            self._run(
                (
                    "kubectl",
                    "replace",
                    "--raw",
                    f"/api/v1/namespaces/{self.namespace}/finalize",
                    "-f",
                    payload_file.name,
                )
            )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            existing = self._run(
                ("kubectl", "get", "namespace", self.namespace, "-o", "name"),
                allowed_codes={0, 1},
            )
            if existing.return_code != 0:
                return
            time.sleep(1)
        raise RuntimeError(
            f"namespace {self.namespace} remained after force-finalizing its E2E-only finalizers"
        )
