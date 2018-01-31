from .forms import OrganizationCreateForm
from datetime import datetime
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_babel import format_datetime
from kqueen_ui.blueprints.ui.utils import sanitize_resource_metadata
from kqueen_ui.generic_views import KQueenView
from kqueen_ui.utils.wrappers import superadmin_required
from slugify import slugify

import logging

logger = logging.getLogger(__name__)
manager = Blueprint('manager', __name__, template_folder='templates')


class Overview(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']

    def handle(self):
        organizations = self.kqueen_request('organization', 'list')
        for organization in organizations:
            organization['created_at'] = format_datetime(organization['created_at'])
        return render_template('manager/overview.html', organizations=organizations)


class DataClusters(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']

    def handle(self):
        clusters = self.kqueen_request('cluster', 'list', fnkwargs={'all_namespaces': True})
        clusters, _, _ = sanitize_resource_metadata(session, clusters, [])
        clusters.sort(key=lambda k: (k['namespace'], k['created_at'], k['name']))
        data = {
            'response': 200,
            'body': render_template('manager/partial/cluster_table.html', clusters=clusters)
        }
        return jsonify(data)


class DataProvisioners(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']

    def handle(self):
        provisioners = self.kqueen_request('provisioner', 'list', fnkwargs={'all_namespaces': True})
        _, provisioners, _ = sanitize_resource_metadata(session, [], provisioners)
        provisioners.sort(key=lambda k: (k['namespace'], k['created_at'], k['name']))
        data = {
            'response': 200,
            'body': render_template('manager/partial/provisioner_table.html', provisioners=provisioners)
        }
        return jsonify(data)


class OrganizationDelete(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, organization_id):
        organization = self.kqueen_request('organization', 'get', fnargs=(organization_id,))
        deletable = self.kqueen_request('organization', 'deletable', fnargs=(organization_id,))
        if not deletable.get('deletable', False):
            resources = ','.join(['{} {}'.format(r['object'], r['name']) for r in deletable.get('remaining', [])])
            flash('Cannot delete organization {}, before deleting its resources: {}'.format(organization['name'], resources), 'warning')
            return redirect(request.environ.get('HTTP_REFERER', url_for('manager.overview')))
        self.kqueen_request('organization', 'delete', fnargs=(organization_id,))
        flash('Organization {} successfully deleted.'.format(organization['name']), 'success')
        return redirect(request.environ.get('HTTP_REFERER', url_for('manager.overview')))


class OrganizationCreate(KQueenView):
    methods = ['GET', 'POST']

    def handle(self):
        form = OrganizationCreateForm()
        if form.validate_on_submit():
            organization_kw = {
                'name': form.organization_name.data,
                'namespace': slugify(form.organization_name.data),
                'created_at': datetime.utcnow()
            }
            organization = self.kqueen_request('organization', 'create', fnargs=(organization_kw,))
            flash('Organization {} successfully created'.format(form.organization_name.data), 'success')
            return redirect(url_for('manager.overview'))
        return render_template('manager/organization_create.html', form=form)


manager.add_url_rule('/', view_func=Overview.as_view('overview'))
manager.add_url_rule('/data/clusters', view_func=DataClusters.as_view('data_clusters'))
manager.add_url_rule('/data/provisioners', view_func=DataProvisioners.as_view('data_provisioners'))
manager.add_url_rule('/organization/create', view_func=OrganizationCreate.as_view('organization_create'))
manager.add_url_rule('/organization/<organization_id>/delete', view_func=OrganizationDelete.as_view('organization_delete'))
