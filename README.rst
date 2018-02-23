KQueen UI - UI for Kubernetes cluster manager
=============================================

.. image:: https://travis-ci.org/Mirantis/kqueen-ui.svg?branch=master
    :target: https://travis-ci.org/Mirantis/kqueen-ui

.. image:: https://coveralls.io/repos/github/Mirantis/kqueen-ui/badge.svg?branch=master
    :target: https://coveralls.io/github/Mirantis/kqueen-ui?branch=master

.. image:: https://readthedocs.org/projects/kqueen-ui/badge/?version=latest
    :target: http://kqueen-ui.readthedocs.io/en/latest/

Overview
--------

UI project for Mirantis KQueen, more information's in `KQueen repository <https://github.com/Mirantis/kqueen>`_.


Requirements
------------


 -  Python v3.6 and higher.
 -  Pip v3 and higher.
 -  NodeJS
 -  Docker stable release (v17.03 and higher is preferable).
 -  Docker-compose stable release (v1.16.0 and higher is preferable).


Development
-----------

- Bootstrap kqueen-ui environment. You need running KQueen backend app to connect to.
   To run it, please refer to `KQueen project documentation <https://github.com/Mirantis/kqueen/blob/master/README.rst>`_

  ::

    virtualenv -p /usr/bin/python3 kqueen-ui
    source ./kqueen-ui/bin/activate

    or if you have *virtualenvwrapper* installed

  ::

    mkvirtualenv -p /usr/bin/python3 kqueen-ui

- Install Python dependencies

  ::

    pip3 install -e ".[dev]"
    pip3 install --editable .

- Install npm and gulp

  ::

    sudo npm install
    sudo npm install -g gulp

- Run gulp tasks to handle static files and etc.

  ::

    sudo gulp build

- Optionally start mail server container. It is used to send confirmation emails during new user creation.

    docker-compose -f docker-compose.mail.yml up -d

- Start UI service by typing

  ::

    kqueen_ui

Configuration
-------------

We load configuration from file ``config/dev.py`` by default and this
can be configured by ``KQUEENUI_CONFIG_FILE`` environment variable. Any
environment variable matching name ``KQUEENUI_*`` will be loaded and saved
to configuration.

Documentation
-------------

For full documenation please refer to
`kqueen-ui.readthedocs.io <http://kqueen-ui.readthedocs.io>`__.

DEMOs
-----

**Generic KQueen Overview**

.. image:: https://img.youtube.com/vi/PCAwCxPQc2A/0.jpg
   :target: https://www.youtube.com/watch?v=PCAwCxPQc2A&t=1s

**AKS (Azure) in KQueen**

.. image:: https://img.youtube.com/vi/xHydnJGcs2k/0.jpg
   :target: https://youtu.be/xHydnJGcs2k
