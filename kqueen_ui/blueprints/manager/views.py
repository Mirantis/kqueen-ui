from flask import Blueprint, render_template
from kqueen_ui.generic_views import KQueenView
from kqueen_ui.utils.wrappers import superadmin_required

import logging

logger = logging.getLogger(__name__)
manager = Blueprint('manager', __name__, template_folder='templates')


class Overview(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']

    def handle(self):
        return render_template('manager/overview.html')

manager.add_url_rule('/', view_func=Overview.as_view('overview'))
