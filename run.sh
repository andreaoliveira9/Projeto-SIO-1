#!/bin/bash

while getopts "a:p:" opt; do
  case $opt in
  a) APP="$OPTARG"
	;;
	p) PORT=$OPTARG
	;;
	\?) echo "Invalid option -$OPTARG" >&2
	;;
  esac
done

export FLASK_APP=$APP/__init__.py
export FLASK_ENV=development
export FLASK_DEBUG=1
export FLASK_RUN_PORT=$PORT
flask run