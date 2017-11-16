from flask.ext.babel import format_datetime
from flask_table import Table, Col, DatetimeCol as BaseDatetimeCol, LinkCol


class DatetimeCol(BaseDatetimeCol):
    def td_format(self, content):
        if content:
            return format_datetime(content, self.datetime_format)
        else:
            return ''


class DeleteCol(LinkCol):
    def __init__(self, *args, **kwargs):
        kwargs['column_html_attrs'] = {'class': 'action_column'}
        super(DeleteCol, self).__init__(*args, **kwargs)


class StatusCol(Col):
    def __init__(self, *args, **kwargs):
        kwargs['column_html_attrs'] = {'class': 'status_column'}
        super(StatusCol, self).__init__(*args, **kwargs)


class ClusterTable(Table):
    # Table meta
    classes = ['table', 'table-hover']
    # Table fields
    name = LinkCol(
        'Name',
        'ui.cluster_detail',
        attr_list=['name'],
        url_kwargs=dict(cluster_id='id')
    )
    # name = Col('Name')
    provisioner = Col('Provisioner', attr='provisioner.name')
    state = StatusCol('Status')
    created_at = DatetimeCol('Created')
    delete = DeleteCol(
        'Delete',
        'ui.cluster_delete',
        url_kwargs=dict(cluster_id='id')
    )


class OrganizationMembersTable(Table):
    # Table meta
    classes = ['table', 'table-hover']
    # Table fields
    username = Col('Name')
    email = Col('Email')
    # name = Col('Name')
    role = Col('Role')
    state = StatusCol('Status')
    created_at = DatetimeCol('Created')
    delete = DeleteCol(
        'Delete',
        'ui.user_delete',
        url_kwargs=dict(user_id='id')
    )


class ProvisionerTable(Table):
    # Table meta
    classes = ['table', 'table-hover']
    # Table fields
    name = Col('Name')
    engine_name = Col('Engine')
    state = StatusCol('Status')
    created_at = DatetimeCol('Created')
    delete = DeleteCol(
        'Delete',
        'ui.provisioner_delete',
        url_kwargs=dict(provisioner_id='id')
    )
