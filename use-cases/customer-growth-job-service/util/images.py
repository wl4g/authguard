"""Single image matrix for every E2E build, Helm release and Compose service."""
from __future__ import annotations
from dataclasses import dataclass, fields
import os
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


class E2EImagesDefinitions:
    DEFAULT_PLATFORM = "linux/amd64"
    WORKLOADS = (
        "go-sqlx",
        "rust-sqlx",
        "python-sqlalchemy",
        "spring-jdbc",
        "spring-jpa",
    )
    LOCAL_IMAGES = {
        "authguard": "registry.cn-shenzhen.aliyuncs.com/wl4g/authguard:e2e-local",
        "web": "registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-web:e2e-local",
        "mock-idp": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-mock-idp:e2e-local",
        "go-sqlx": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-go-sqlx:e2e-local",
        "rust-sqlx": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-rust-sqlx:e2e-local",
        "python-sqlalchemy": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-python-sqlalchemy:e2e-local",
        "spring-jdbc": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-spring-jdbc:e2e-local",
        "spring-jpa": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-spring-jpa:e2e-local",
    }
    _REGIONS = {
        "aliyun": {
            "envoy": "registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_envoy:distroless-v1.36.4",
            "envoy_gateway": "registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_gateway:v1.9.0",
            "redis": "registry.cn-shenzhen.aliyuncs.com/wl4g-k8s/bitnami_redis-cluster:7.0.14",
            "keycloak": "registry.cn-shenzhen.aliyuncs.com/wl4g/keycloak:26.7.0",
            "ldap": "registry.cn-shenzhen.aliyuncs.com/wl4g/glauth:v2.5.0",
            "jaeger": "registry.cn-shenzhen.aliyuncs.com/wl4g/jaegertracing_all-in-one:1.76.0",
            "postgres": "registry.cn-shenzhen.aliyuncs.com/wl4g/bitnami_postgresql:18.3",
            "anvil": "registry.cn-shenzhen.aliyuncs.com/wl4g/foundry_anvil:1.7.1",
            "solana": "registry.cn-shenzhen.aliyuncs.com/wl4g/anza_solana:3.1.14",
            "web_builder": "registry.cn-shenzhen.aliyuncs.com/wl4g/node:22-alpine",
            "web_runtime": "registry.cn-shenzhen.aliyuncs.com/wl4g/nginxinc_nginx-unprivileged:1.27-alpine",
            "chain_builder": "registry.cn-shenzhen.aliyuncs.com/wl4g/rust:1.99.1-slim",
            "go_builder": "registry.cn-shenzhen.aliyuncs.com/wl4g/golang:1.26-alpine",
            "rust_builder": "registry.cn-shenzhen.aliyuncs.com/wl4g/rust:1.99.1-slim",
            "python_runtime": "registry.cn-shenzhen.aliyuncs.com/wl4g/python:3.12-slim",
            "maven_builder": "registry.cn-shenzhen.aliyuncs.com/wl4g/maven:3.9.9-eclipse-temurin-17",
            "java_runtime": "registry.cn-shenzhen.aliyuncs.com/wl4g/eclipse-temurin:17-jre",
            "debian": "registry.cn-shenzhen.aliyuncs.com/wl4g/debian:trixie-slim",
        },
        "global": {
            "envoy": "docker.io/envoyproxy/envoy:distroless-v1.36.4",
            "envoy_gateway": "docker.io/envoyproxy/gateway:v1.9.0",
            "redis": "docker.io/bitnamilegacy/redis-cluster:7.0.14",
            "keycloak": "quay.io/keycloak/keycloak:26.7.0",
            "ldap": "docker.io/glauth/glauth:v2.5.0",
            "jaeger": "docker.io/jaegertracing/all-in-one:1.76.0",
            "postgres": "docker.io/bitnami/postgresql@sha256:7d77a46bbf200709237318c27dec0eaeae2520e403dd18fdebde2be7a6b04993",
            "anvil": "authguard-e2e/foundry-anvil:e2e-local",
            "solana": "authguard-e2e/anza-solana:e2e-local",
            "web_builder": "docker.io/library/node:22-alpine",
            "web_runtime": "docker.io/nginxinc/nginx-unprivileged:1.27-alpine",
            "chain_builder": "docker.io/library/rust:1.99.1-slim",
            "go_builder": "docker.io/library/golang:1.26-alpine",
            "rust_builder": "docker.io/library/rust:1.99.1-slim",
            "python_runtime": "docker.io/library/python:3.12-slim",
            "maven_builder": "docker.io/library/maven:3.9.9-eclipse-temurin-17",
            "java_runtime": "docker.io/library/eclipse-temurin:17-jre",
            "debian": "docker.io/library/debian:trixie-slim",
        },
    }
    COMPONENT_ENV = {
        "authguard": "AUTHGUARD_E2E_AUTHGUARD_IMAGE",
        "web": "AUTHGUARD_E2E_WEB_IMAGE",
        "mock-idp": "AUTHGUARD_E2E_MOCK_IDP_IMAGE",
        "envoy": "AUTHGUARD_E2E_ENVOY_IMAGE",
        "envoy_gateway": "AUTHGUARD_E2E_ENVOY_GATEWAY_IMAGE",
        "redis": "AUTHGUARD_E2E_REDIS_IMAGE",
        "keycloak": "AUTHGUARD_E2E_KEYCLOAK_IMAGE",
        "ldap": "AUTHGUARD_E2E_LDAP_IMAGE",
        "jaeger": "AUTHGUARD_E2E_JAEGER_IMAGE",
        "postgres": "AUTHGUARD_E2E_POSTGRES_IMAGE",
        "anvil": "AUTHGUARD_E2E_ANVIL_IMAGE",
        "solana": "AUTHGUARD_E2E_SOLANA_IMAGE",
        "go-sqlx": "AUTHGUARD_E2E_GO_SQLX_IMAGE",
        "rust-sqlx": "AUTHGUARD_E2E_RUST_SQLX_IMAGE",
        "python-sqlalchemy": "AUTHGUARD_E2E_PYTHON_SQLALCHEMY_IMAGE",
        "spring-jdbc": "AUTHGUARD_E2E_SPRING_JDBC_IMAGE",
        "spring-jpa": "AUTHGUARD_E2E_SPRING_JPA_IMAGE",
    }
    BUILD_ENV = {
        "RUST_BUILDER_IMAGE": "rust_builder",
        "GO_IMAGE": "go_builder",
        "PYTHON_IMAGE": "python_runtime",
        "MAVEN_IMAGE": "maven_builder",
        "JAVA_IMAGE": "java_runtime",
        "NODE_IMAGE": "web_builder",
        "WEB_IMAGE": "web_runtime",
        "DEBIAN_IMAGE": "debian",
        "RUST_IMAGE": "chain_builder",
    }
    HELM_IMAGES = {
        "keycloak.image": "keycloak",
        "ldap.image": "ldap",
        "jaeger.image": "jaeger",
        "postgresql.image": "postgres",
        "anvil.image": "anvil",
        "solana.image": "solana",
        "mockIdp.image": "mock-idp",
        "image": "envoy",
        "envoy_gateway.global.images.envoyGateway.image": "envoy_gateway",
        "envoy_gateway.global.images.envoyProxy.image": "envoy",
    }
    MATRIX = {
        region: {arch: references for arch in ("amd64", "arm64")}
        for region, references in _REGIONS.items()
    }

    @staticmethod
    def source(environment) -> str:
        explicit = environment.get("AUTHGUARD_E2E_IMAGE_SOURCE")
        if explicit:
            source = explicit.lower()
            if source not in {"aliyun", "global"}:
                raise ValueError("AUTHGUARD_E2E_IMAGE_SOURCE must be aliyun or global")
            return source
        value = environment.get("IN_GFW", environment.get("IN_CN_GFW"))
        if value is not None:
            if str(value).lower() not in {
                "true",
                "false",
                "1",
                "0",
                "in_gfw",
                "non_gfw",
            }:
                raise ValueError("IN_GFW/IN_CN_GFW must be true or false")
            return (
                "aliyun" if str(value).lower() in {"true", "1", "in_gfw"} else "global"
            )
        return (
            "global"
            if str(environment.get("NON_GFW", "false")).lower() in {"true", "1"}
            else "aliyun"
        )

    @classmethod
    def references(cls, environment):
        source = cls.source(environment)
        if source not in cls.MATRIX:
            raise ValueError("AUTHGUARD_E2E_IMAGE_SOURCE must be aliyun or global")
        architecture = environment.get(
            "AUTHGUARD_E2E_PLATFORM",
            environment.get("DOCKER_DEFAULT_PLATFORM", cls.DEFAULT_PLATFORM),
        ).split("/")[-1]
        architecture = "arm64" if architecture == "aarch64" else architecture
        if architecture not in {"amd64", "arm64"}:
            raise ValueError(f"unsupported E2E image architecture: {architecture}")
        images = {**cls.MATRIX[source][architecture], **cls.LOCAL_IMAGES}
        for key, variable in cls.COMPONENT_ENV.items():
            images[key] = environment.get(variable, images[key])
        for variable, key in cls.BUILD_ENV.items():
            images[key] = environment.get(variable, images[key])
        return images

    @classmethod
    def environment(cls, environment=None):
        environment = os.environ if environment is None else environment
        images = cls.references(environment)
        return {
            "AUTHGUARD_E2E_IMAGE_SOURCE": cls.source(environment),
            "DOCKER_DEFAULT_PLATFORM": environment.get(
                "AUTHGUARD_E2E_PLATFORM",
                environment.get("DOCKER_DEFAULT_PLATFORM", cls.DEFAULT_PLATFORM),
            ),
            **{variable: images[key] for key, variable in cls.COMPONENT_ENV.items()},
            **{
                variable: environment.get(variable, images[key])
                for variable, key in cls.BUILD_ENV.items()
            },
        }

    @classmethod
    def helm_values(cls, environment=None):
        images = cls.references(os.environ if environment is None else environment)
        values = {path: images[key] for path, key in cls.HELM_IMAGES.items()}
        values.update({f"workloads.{key}.image": images[key] for key in cls.WORKLOADS})
        registry, repository = images["redis"].split("/", 1)
        repository, tag = repository.rsplit(":", 1)
        values.update(
            {
                "redis_cluster.image.registry": registry,
                "redis_cluster.image.repository": repository,
                "redis_cluster.image.tag": tag,
            }
        )
        for component, key in (
            ("authn", "authguard"),
            ("authz", "authguard"),
            ("web", "web"),
        ):
            repository, tag = images[key].rsplit(":", 1)
            prefix = f"authguard-middleware.authguard.{component}.image"
            values.update({f"{prefix}.repository": repository, f"{prefix}.tag": tag})
        for component, key in (("redis_cluster", "redis"), ("postgresql", "postgres")):
            registry, repository = images[key].split("/", 1)
            name, separator, digest = repository.partition("@")
            name, tag = (name, "") if separator else name.rsplit(":", 1)
            prefix = f"authguard-middleware.{component}.image"
            values.update(
                {
                    f"{prefix}.registry": registry,
                    f"{prefix}.repository": name,
                    f"{prefix}.tag": tag,
                    f"{prefix}.digest": digest,
                }
            )
        for key, image in (("envoyGateway", "envoy_gateway"), ("envoyProxy", "envoy")):
            values[
                f"authguard-middleware.envoy_gateway.global.images.{key}.image"
            ] = images[image]
        return values

    @classmethod
    def build_arguments(cls, dockerfile, environment=None):
        environment = cls.environment(environment)
        names = re.findall("(?m)^ARG (\\w*IMAGE)(?:=|$)", Path(dockerfile).read_text())
        return tuple(
            (
                value
                for name in names
                for value in ("--build-arg", f"{name}={environment[name]}")
            )
        )

    @classmethod
    def main(cls):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from util.constant import E2EOtherDefinitions

        environment = os.environ.copy()
        environment.update(cls.environment(environment))
        command = sys.argv[1:]
        if command[:1] == ["--"]:
            command = command[1:]
        if not command:
            print(
                "\n".join(
                    (
                        f"{key}={value}"
                        for key, value in cls.environment(environment).items()
                    )
                )
            )
            return 0
        executable = Path(command[0]).name
        if (
            executable in {"docker", "podman"}
            and "build" in command
            and ("compose" not in command)
        ):
            flag = (
                "-f" if "-f" in command else "--file" if "--file" in command else None
            )
            dockerfile = Path(
                command[command.index(flag) + 1] if flag else "Dockerfile"
            )
            position = command.index("build") + 1
            command[position:position] = cls.build_arguments(dockerfile, environment)
            if not any(
                (
                    item in {"-t", "--tag"} or item.startswith("--tag=")
                    for item in command
                )
            ):
                component = (
                    "authguard"
                    if dockerfile.resolve()
                    == E2EOtherDefinitions.PROJECT_ROOT / "deploy/docker/Dockerfile"
                    else "web"
                    if dockerfile.resolve()
                    == E2EOtherDefinitions.PROJECT_ROOT / "web/Dockerfile"
                    else next(
                        (
                            key
                            for key, directory in E2EOtherDefinitions.COMPONENTS.items()
                            if directory == dockerfile.parent.name
                        )
                    )
                )
                command[position:position] = [
                    "--tag",
                    cls.references(environment)[component],
                ]
        if executable == "helm" and any(
            (item in command for item in ("install", "upgrade", "template", "lint"))
        ):
            chart = next(
                (
                    Path(arg).resolve()
                    for arg in command
                    if (Path(arg) / "Chart.yaml").is_file()
                ),
                None,
            )
            component = next(
                (
                    key
                    for key in E2EOtherDefinitions.COMPONENTS
                    if E2EOtherDefinitions.chart(key).resolve() == chart
                ),
                None,
            )
            if component is None:
                raise ValueError(
                    "select a component Chart under deploy/<component>/helm"
                )
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as values:
                json.dump(
                    E2EOtherDefinitions.select(
                        E2EOtherDefinitions.values(environment), component
                    ),
                    values,
                )
                values.flush()
                position = next(
                    (
                        index + 1
                        for index, argument in enumerate(command)
                        if argument in {"install", "upgrade", "template", "lint"}
                    )
                )
                command[position:position] = ["-f", values.name]
                return subprocess.run(command, env=environment).returncode
        return subprocess.run(command, env=environment).returncode

    @dataclass(frozen=True)
    class E2EImageCatalog:
        """Pinned equivalent images selected for the build host's network path."""

        source: str
        envoy: str
        envoy_gateway: str
        redis: str
        keycloak: str
        ldap: str
        jaeger: str
        postgres: str
        anvil: str
        solana: str
        web_builder: str
        web_runtime: str
        chain_builder: str
        go_builder: str
        rust_builder: str
        python_runtime: str
        maven_builder: str
        java_runtime: str
        debian: str
        local_chain_images: tuple[str, ...] = ()

        @classmethod
        def from_environment(cls, environment=None) -> "E2EImageCatalog":
            environment = os.environ if environment is None else environment
            source = E2EImagesDefinitions.source(environment)
            images = E2EImagesDefinitions.references(environment)
            names = {field.name for field in fields(cls)} - {
                "source",
                "local_chain_images",
            }
            local = (
                tuple((images[key] for key in ("anvil", "solana")))
                if source == "global"
                else ()
            )
            return cls(
                source=source,
                local_chain_images=local,
                **{key: images[key] for key in names},
            )

        @property
        def pullable_images(self) -> tuple[str, ...]:
            images = (
                self.envoy,
                self.envoy_gateway,
                self.redis,
                self.keycloak,
                self.ldap,
                self.jaeger,
                self.postgres,
                self.anvil,
                self.solana,
            )
            return tuple(
                (image for image in images if image not in self.local_chain_images)
            )

        @property
        def docker_pullable_images(self) -> tuple[str, ...]:
            return tuple(
                (
                    image
                    for image in self.all_images
                    if image != self.envoy_gateway
                    and image not in self.local_chain_images
                )
            )

        @property
        def all_images(self) -> tuple[str, ...]:
            return (
                self.envoy,
                self.envoy_gateway,
                self.redis,
                self.keycloak,
                self.ldap,
                self.jaeger,
                self.postgres,
                self.anvil,
                self.solana,
            )

        @staticmethod
        def helm_image_parts(image: str) -> tuple[str, str, str]:
            registry, repository_and_tag = image.split("/", 1)
            repository, tag = repository_and_tag.rsplit(":", 1)
            return (registry, repository, tag)


E2EImagesDefinitions.E2E_IMAGES = (
    E2EImagesDefinitions.E2EImageCatalog.from_environment()
)
E2EImagesDefinitions.DEFAULT_AUTHGUARD_IMAGE = E2EImagesDefinitions.LOCAL_IMAGES[
    "authguard"
]
E2EImagesDefinitions.DEFAULT_AUTHGUARD_WEB_IMAGE = E2EImagesDefinitions.LOCAL_IMAGES[
    "web"
]
E2EImagesDefinitions.AUTHGUARD_IMAGE = os.getenv(
    "AUTHGUARD_E2E_AUTHGUARD_IMAGE", E2EImagesDefinitions.DEFAULT_AUTHGUARD_IMAGE
)
E2EImagesDefinitions.AUTHGUARD_WEB_IMAGE = os.getenv(
    "AUTHGUARD_E2E_WEB_IMAGE", E2EImagesDefinitions.DEFAULT_AUTHGUARD_WEB_IMAGE
)
E2EImagesDefinitions.MOCK_IDP_IMAGE = E2EImagesDefinitions.references(os.environ)[
    "mock-idp"
]
E2EImagesDefinitions.WORKLOAD_IMAGES = {
    key: E2EImagesDefinitions.references(os.environ)[key]
    for key in E2EImagesDefinitions.WORKLOADS
}
if __name__ == "__main__":
    raise SystemExit(E2EImagesDefinitions.main())
