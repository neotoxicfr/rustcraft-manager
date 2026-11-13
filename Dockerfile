# syntax=docker/dockerfile:1.7
#
# Image de Rustcraft Manager (multi-étapes). Contexte = racine du dépôt :
#   docker buildx build -f Dockerfile -t rustcraft-manager:dev --platform linux/amd64 \
#     --build-arg RCM_GIT_COMMIT=$(git rev-parse HEAD) --load .
#   docker buildx build -f Dockerfile --platform linux/amd64,linux/arm64 -t <registre>/rustcraft-manager:<version> --push .
# Multi-architecture SANS émulation : les étapes de construction tournent sur la plateforme de
# l'hôte ($BUILDPLATFORM). L'interface (wasm) est construite une seule fois pour toutes les
# architectures ; le binaire est compilé en croisé vers $TARGETARCH (gcc croisé de Debian pour le
# C de SQLite et de ring). L'image finale ne fait que copier : aucune commande sous QEMU.
#
# Lancement :
#   openssl rand -base64 32 > rcm.key && chmod 600 rcm.key     # clé de chiffrement, À PART de /data
#   docker run -d --name rustcraft-manager -p 127.0.0.1:8580:8580 -v rcm-data:/data \
#     -v "$PWD/rcm.key:/run/secrets/rcm_key:ro" -e RCM_ENCRYPTION_KEY_FILE=/run/secrets/rcm_key \
#     rustcraft-manager:dev
#   docker logs rustcraft-manager     # jeton à usage unique du premier compte

# --- Étape 1 : outils de construction (plateforme de l'hôte) -----------------------------------
# Images de base épinglées par empreinte (index multi-architecture lu le 20/10/2026) : une
# reconstruction ne change pas d'image en silence. Mettre les deux à jour ensemble, avec une
# semaine de recul : docker buildx imagetools inspect <image:étiquette>
FROM --platform=$BUILDPLATFORM rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS tools
# Outils de l'interface, mêmes versions que sur le poste de développement.
RUN rustup target add wasm32-unknown-unknown \
 && cargo install --locked trunk --version 0.21.14 \
 && cargo install --locked wasm-bindgen-cli --version 0.2.129
# wasm-opt (binaryen version_133, celle de web/Trunk.toml) : trunk --offline ne télécharge rien.
# Archive de la release officielle, empreinte épinglée par architecture (fichiers .sha256 de la release).
ARG BUILDARCH
RUN case "$BUILDARCH" in \
      amd64|"") a=x86_64; s=2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489 ;; \
      arm64) a=aarch64; s=89c07ea56faf38d0fbecf36ca8ec0721756716185f265b568e133d427f299bf8 ;; \
      *) echo "architecture de construction non prise en charge : $BUILDARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/binaryen.tgz "https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-$a-linux.tar.gz" \
 && echo "$s  /tmp/binaryen.tgz" | sha256sum -c - \
 && tar -xzf /tmp/binaryen.tgz -C /opt \
 && ln -s /opt/binaryen-version_133/bin/wasm-opt /usr/local/bin/wasm-opt \
 && rm /tmp/binaryen.tgz && wasm-opt --version
WORKDIR /src

# --- Étape 2 : interface (wasm, identique pour toutes les architectures) ------------------------
FROM tools AS web
COPY . .
# Le fichier de chaîne d'outils du dépôt vise le poste de développement (cible Windows msvc) :
# l'image utilise sa propre 1.99.
RUN rm -f rust-toolchain.toml && cd web && NO_COLOR=true trunk build --release --offline

# --- Étape 3 : binaire, compilé en croisé vers l'architecture visée ----------------------------
FROM tools AS build
ARG BUILDARCH
ARG TARGETARCH
# Cible Rust et gcc croisé (glibc 2.36 de bookworm, celle de l'image finale debian12). Rien à
# installer quand l'hôte a déjà l'architecture visée.
RUN case "$TARGETARCH" in \
      amd64|"") t=x86_64-unknown-linux-gnu; g=x86_64-linux-gnu; p="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
      arm64) t=aarch64-unknown-linux-gnu; g=aarch64-linux-gnu; p="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
      *) echo "architecture non prise en charge : $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && T=$(echo "$t" | tr 'a-z-' 'A-Z_') && u=$(echo "$t" | tr '-' '_') \
 && { echo "export RUST_TARGET=$t"; \
      if [ "${TARGETARCH:-amd64}" != "${BUILDARCH:-amd64}" ]; then \
        echo "export CARGO_TARGET_${T}_LINKER=$g-gcc CC_$u=$g-gcc AR_$u=$g-ar"; \
      fi; } > /cross.env \
 && if [ "${TARGETARCH:-amd64}" != "${BUILDARCH:-amd64}" ]; then \
      apt-get update && apt-get install -y --no-install-recommends $p && rm -rf /var/lib/apt/lists/*; \
    fi \
 && rustup target add "$t" && cat /cross.env
COPY . .
RUN rm -f rust-toolchain.toml
COPY --from=web /src/web/dist web/dist
# Commit construit (`.git` n'est pas dans le contexte) : --build-arg RCM_GIT_COMMIT=$(git rev-parse HEAD)
ARG RCM_GIT_COMMIT=inconnu
ENV RCM_GIT_COMMIT=${RCM_GIT_COMMIT}
RUN . /cross.env \
 && cargo build --release --locked --target "$RUST_TARGET" -p rc-manager --bin rustcraft-manager \
 && install -D "target/$RUST_TARGET/release/rustcraft-manager" /out/rustcraft-manager \
 && mkdir -p /out/data

# --- Étape 4 : image finale minimale, sans shell, utilisateur non root ------------------------
# Java des serveurs (Temurin, téléchargé à l'exécution dans /data/java) : le JRE ne demande que la
# glibc fournie ici (libc, libdl, libm, libpthread, librt ; vérifié par readelf sur le JRE 25
# Linux), zlib et freetype sont dans le JRE, X11 et ALSA ne servent qu'à l'affichage (la JVM tourne
# sans affichage). Lancer avec `init: true` (README) : les processus Java terminés sont récoltés.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /out/rustcraft-manager /usr/local/bin/rustcraft-manager
# Dossier de données appartenant à l'utilisateur de l'image (uid 65532) : un volume nommé en hérite.
COPY --from=build --chown=65532:65532 /out/data /data
# RCM_COOKIE_SECURE=always : l'image n'est servie que derrière un mandataire HTTPS, le cookie est
# `Secure` (et `__Host-`) même si X-Forwarded-Proto manque. RCM_CONTAINER=true : la clé de
# chiffrement doit venir d'un secret Docker (RCM_ENCRYPTION_KEY_FILE), jamais du volume.
ENV RCM_DATA_DIR=/data \
    RCM_LISTEN=0.0.0.0 \
    RCM_PORT=8580 \
    RCM_COOKIE_SECURE=always \
    RCM_CONTAINER=true
VOLUME ["/data"]
EXPOSE 8580
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/rustcraft-manager", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/rustcraft-manager"]
