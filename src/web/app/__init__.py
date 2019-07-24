from flask import Flask, render_template
from flask.ext.mail import Mail
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bootstrap import Bootstrap

from config import config


class HackedSQLAlchemy(SQLAlchemy):
    """A simple hack to support isolation level"""

    def apply_driver_hacks(self, app, info, options):
        if app.config.get('SQLALCHEMY_ISOLATION_LEVEL'):
            options['isolation_level'] = app.config['SQLALCHEMY_ISOLATION_LEVEL']
        elif info.drivername.startswith('mysql'):
            options['isolation_level'] = 'READ COMMITTED'
        elif info.drivername == 'sqlite':
            options['isolation_level'] = 'READ UNCOMMITTED'
        options['pool_pre_ping'] = True
        super(HackedSQLAlchemy, self).apply_driver_hacks(app, info, options)


mail = Mail()
bootstrap = Bootstrap()
db = HackedSQLAlchemy()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    # initial third party extension
    mail.init_app(app)
    bootstrap.init_app(app)

    # register blueprints
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app


