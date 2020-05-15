# Copyright 2020 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from alembic import op
import sqlalchemy as sa


"""add fip_admin_state_up_and_fip_type

Revision ID: d6083e887554
Revises: 5f1059595298
Create Date: 2020-05-12 11:33:40.844637

"""

# revision identifiers, used by Alembic.
revision = 'd6083e887554'
down_revision = '5f1059595298'


def upgrade():
    op.add_column('floatingips', sa.Column('admin_state_up', sa.Boolean()))
    op.add_column('floatingips', sa.Column('fip_type', sa.String(15)))
