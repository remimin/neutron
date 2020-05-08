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


"""add routers enable snat66

Revision ID: 5f1059595298
Revises: 867d39095bf4
Create Date: 2020-04-22 13:26:24.745678

"""

# revision identifiers, used by Alembic.
revision = '5f1059595298'
down_revision = '867d39095bf4'


def upgrade():
    op.add_column('routers', sa.Column('enable_snat66', sa.Boolean(),
                                   nullable=False, server_default=sa.sql.false()))
