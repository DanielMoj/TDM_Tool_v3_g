# Dockerfile.app
FROM rocker/shiny:4.3.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev libcurl4-openssl-dev libssl-dev libfontconfig1-dev \
    libharfbuzz-dev libfribidi-dev pandoc pandoc-citeproc \
    libglpk40 libgsl-dev liblapack-dev libblas-dev libudunits2-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /srv/app
WORKDIR /srv/app

RUN R -e "install.packages(c('zoo','posterior','shiny','bslib','ggplot2','dplyr','DT','jsonlite','glue','readr','tibble','lubridate','deSolve','numDeriv','MASS','rmarkdown','promises','future'))"

EXPOSE 3838
CMD ["/usr/bin/shiny-server"]
