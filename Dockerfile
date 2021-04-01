# Dockerfile used to build container based on SimpleCV
# and then append other packages to enable Django

# specify base image
FROM jupyter/minimal-notebook
# FROM jupyter/tensorflow-notebook

# provide creator/maintainer of this Dockerfile
MAINTAINER Anthony Yee <smyee@yahoo.com>
RUN pip install SQLAlchemy
RUN pip install pytenable
