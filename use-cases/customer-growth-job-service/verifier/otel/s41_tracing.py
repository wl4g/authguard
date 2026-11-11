from __future__ import annotations
import yaml
import json
from util.constant import E2EOtherDefinitions
from util.images import E2EImagesDefinitions
from verifier.context import BaseVerifier, VerificationContext, VerificationResult


class E2ES41TracingVerifier(BaseVerifier):
    scenario_id = "41"
    title = "Observability: tracing across AuthN, AuthZ and business services"

    def deploy(self, context: VerificationContext) -> None:
        """Reuse the deployment owned by scenario 00."""

    def init(self, context: VerificationContext) -> None:
        """No additional input initialization is required."""

    def verifier(self, context: VerificationContext) -> VerificationResult:
        return self.execute(self._verify)

    def _verify(self) -> None:
        self.step(
            "verify deterministic 100-percent tracing configuration",
            self._verify_sampling,
        )
        self.step(
            "query Jaeger services and recent trace inventory",
            self._verify_trace_inventory,
        )

    def _verify_trace_inventory(self) -> None:
        """Require persisted traces from both AuthGuard services and every Biz app."""
        expected = {
            "authguard-authn",
            "authguard-authz",
            *set(E2EImagesDefinitions.WORKLOAD_IMAGES),
        }
        with self._forward_service(self.jaeger_service, 16686) as port:
            jaeger = self._jaeger_query(port)
            jaeger.require_services(expected)
            jaeger.require_recent_traces(expected)
        self.details.append(
            "Jaeger Query API contains recent traces from AuthN, AuthZ, and all five Biz services"
        )

    def _verify_sampling(self) -> None:
        configuration = self.context.state.get("authguard_config")
        if configuration is None:
            configuration = yaml.safe_load(
                (
                    E2EOtherDefinitions.AUTHGUARD_CONFIG_DIR / "authguard.yaml"
                ).read_text()
            )
        otel = configuration["mgmt"]["otel"]
        if otel.get("enabled") is not True or float(otel.get("sample_rate", 0)) != 1.0:
            raise RuntimeError(
                "AuthGuard E2E tracing must be enabled with sample_rate=1.0"
            )
        if self.context.deployer == "kubernetes":
            deployments = self.infrastructure.resource("deployments")["items"]
            for component in E2EImagesDefinitions.WORKLOAD_IMAGES:
                name = self.workload_service(component)
                deployment = next(
                    (d for d in deployments if d["metadata"]["name"] == name), None
                )
                if deployment is None:
                    raise RuntimeError(f"missing traced workload deployment {name}")
                for container in deployment["spec"]["template"]["spec"]["containers"]:
                    environment = {
                        e["name"]: e.get("value") for e in container.get("env", [])
                    }
                    if environment.get("OTEL_TRACES_SAMPLER") != "always_on":
                        raise RuntimeError(
                            f"{name}: OTEL_TRACES_SAMPLER must be always_on"
                        )
        else:
            ids = self.infrastructure._compose(
                "ps", "-q", *E2EImagesDefinitions.WORKLOAD_IMAGES
            ).output.split()
            containers = json.loads(self._run(("docker", "inspect", *ids)).output)
            if len(containers) != len(E2EImagesDefinitions.WORKLOAD_IMAGES):
                raise RuntimeError("missing traced Docker workloads")
            for container in containers:
                if "OTEL_TRACES_SAMPLER=always_on" not in container["Config"]["Env"]:
                    raise RuntimeError(
                        "every Docker workload must use the always_on OTEL sampler"
                    )
        self.details.append(
            "AuthGuard sample_rate is 1.0 and every business workload uses OTEL_TRACES_SAMPLER=always_on"
        )
