# docker/ctf-sage/Dockerfile
#
# Dedicated SageMath image (UPGRADE_PLAN.md §6, RESOLVED decision 1).
#
# WHY a separate image:
#   SageMath is ~2.5GB and ships its own Python interpreter; there is no working
#   standalone pip package on python:3.12-slim. Bundling it into ctf-crypto would
#   bloat that image for every crypto tool call. Instead this image is:
#     - lazy-built ONLY when a Sage tool (run_sage) is first invoked, and
#     - prunable by the idle-TTL reaper when unused (D6 / Phase 4).
#   ctf-crypto stays lean (z3, openssl, RsaCtfTool, fpylll/flatter, sympy, pycryptodome).
#
# The upstream sagemath/sagemath image already runs as the non-root user `sage`
# (uid/gid 1000), which matches the toolkit's hardened container model
# (docker_runner runs containers as 1000:1000, cap_drop ALL, no-new-privileges).
#
# Base is intentionally pinned to a concrete Sage release tag (NOT :latest) so the
# warm/lazy build is reproducible across friends' clones. Bump deliberately.
FROM sagemath/sagemath:10.4

LABEL maintainer="CTF Toolkit"
LABEL description="CTF SageMath image - algebra/number-theory/lattice solving for run_sage"

# sagemath/sagemath defaults to the `sage` user and WORKDIR. The toolkit mounts the
# host workspace at /workspace and runs scripts from there; ensure it exists and is
# traversable by uid 1000 (the user docker_runner launches the container as).
USER root
RUN mkdir -p /workspace && chown 1000:1000 /workspace
USER sage

WORKDIR /workspace

# Default command kept as bash for ad-hoc use; run_sage overrides with `sage <script>`.
CMD ["/bin/bash"]
