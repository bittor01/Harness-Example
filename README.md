# Harness Example

This repository is a simple example of a workflow for experimenting with agentic loops. It is meant as a lightweight starting point for learning how to chain reasoning, tool use, and model-driven actions together in a controlled environment.

## What this project is

This harness provides a small Docker-based example that runs a Python app against a local model endpoint. The goal is not to be a production framework, but to give you a straightforward way to explore the mechanics of an agent-like workflow without needing to set up everything manually on your host machine.

## Prerequisites

### General requirements

- Docker installed and running
- Docker Compose available
- A machine with a capable GPU is strongly recommended

### Hardware and drivers

- Ideally use a GPU with at least 6 GB of VRAM
- Make sure your GPU drivers are up to date
- For NVIDIA GPUs, the Studio driver is ideally preferred over the Game Ready driver for development and local inference workloads

### Operating system notes

- For Windows, install Docker Desktop
- For non-Windows environments, install Docker and Docker Compose and ensure your setup can run containers normally
- On some non-Windows setups, Docker Model Runner may need to be installed separately if your environment does not expose local model serving by default

> The application dependencies and runtime environment should be handled inside the container, so you should not need to install Python packages directly on your host.

## Quick start

From the repository root, build and start the example container:

```bash
docker compose up -d --build
```

This will build the image and start the container defined in the compose file.

## Working inside the container

You can open a shell in the running container with:

```bash
docker compose exec harnessexample /bin/sh
```

From there, you can run the example app and experiment with prompts by typing the word `prompt` and then the user prompt in quotes.