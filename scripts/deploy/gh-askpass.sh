#!/bin/sh
# GIT_ASKPASS helper for gh-push.ps1. Reads the token from the environment
# (set in memory by gh-push.ps1); never stores or prints it anywhere else.
case "$1" in
  *Username*) echo "x-access-token" ;;
  *) echo "$SHEAF_GH_TOKEN" ;;
esac
