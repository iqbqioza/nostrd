ARG BASE_IMAGE=public.ecr.aws/debian/debian:trixie
FROM ${BASE_IMAGE}

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=${USER_UID}

ENV RUSTUP_HOME=/home/${USERNAME}/.rustup \
    CARGO_HOME=/home/${USERNAME}/.cargo \
    PATH=/home/${USERNAME}/.cargo/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    sudo \
    python3 \
    python3-pip \
    ripgrep \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd --uid ${USER_UID} --gid ${USER_GID} -m -s /bin/bash ${USERNAME} \
    && echo "${USERNAME} ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME}

USER ${USERNAME}

RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path; \
    rustup component add rustfmt clippy rust-src rust-analyzer; \
    rustc --version; \
    cargo --version; \
    rustfmt --version; \
    cargo clippy --version; \
    printf '[[ -d "${CARGO_HOME:-$HOME/.cargo}/bin" ]] && export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"\n' >> ~/.bashrc

WORKDIR /workspaces

CMD ["/bin/bash"]
