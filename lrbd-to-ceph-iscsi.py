import datetime
import glob
import json
import logging
import os
import pprint
import rados

# TODO switch to rtslib_fb
from rtslib.root import RTSRoot


class LrbdConfig():

    def __init__(self):
        f = open('/var/cache/salt/minion/files/base/ceph/igw/cache/lrbd.conf', 'r')
        self.config = json.loads(f.read())

    def get_portal_name(self, ip):
        for portal in self.config['portals']:
            if ip in portal['addresses']:
                return str(portal['name'])
        raise Exception("IP address '{}' not found in lrbd.conf".format(ip))


class CephIscsiConfig():

    controls_defaults = {
        "block_size": 512,
        "emulate_3pc": 1,
        "emulate_caw": 1,
        "emulate_dpo": 1,
        "emulate_fua_read": 1,
        "emulate_fua_write": 1,
        "emulate_model_alias": 0,
        "emulate_pr": 1,
        "emulate_rest_reord": 1,
        "emulate_tas": 1,
        "emulate_tpu": 0,
        "emulate_tpws": 0,
        "emulate_ua_intlck_ctrl": 0,
        "emulate_write_cache": 0,
        "enforce_pr_isids": 1,
        "force_pr_aptpl": 0,
        "is_nonrot": 1,
        "max_unmap_block_desc_count": 1,
        "max_unmap_lba_count": 8192,
        "max_write_same_len": 65535,
        "optimal_sectors": 8192,
        "pi_prot_type": 0,
        "pi_prot_verify": 0,
        "queue_depth": 256,
        "unmap_granularity": 8192,
        "unmap_granularity_alignment": 0,
        "unmap_zeroes_data": 8192
    }

    errors = []

    def __init__(self, logger):
        self.logger = logger
        self.pprinter = pprint.PrettyPrinter()
        # TODO read from ceph, if exists
        now = CephIscsiConfig._get_time()
        self.config = {
            "disks": {},
            "gateways": {},
            "targets": {},
            "discovery_auth": {'chap': '',
                               'chap_mutual': ''},
            "version": 4,
            "epoch": 0,
            "created": now,
            "updated": now
        }

    @staticmethod
    def _get_time():
        utc = datetime.datetime.utcnow()
        return utc.strftime('%Y/%m/%d %H:%M:%S')

    def add_target(self, target_iqn):
        self.logger.debug('Adding target %s', target_iqn)
        now = CephIscsiConfig._get_time()
        self.config['targets'][target_iqn] = {
            'created': now,
            'disks': [],
            'clients': {},
            'portals': {},
            'groups': {},
            'controls': {}
         }

    @staticmethod
    def _get_pool_id(pool):
        # TODO - get pool id from ceph
        #with rados.Rados(conffile='/etc/ceph/ceph.conf') as cluster:
        #    pool_id = cluster.pool_lookup(pool)
        #return pool_id
        return 1

    def _get_controls(self, pool, image):
        disk_id = '{}.{}'.format(pool, image)
        glob_path = "{}/{}/{}".format('/sys/kernel/config/target',
                                      'core',
                                      'rbd_*/{}/attrib'.format(disk_id))
        paths = glob.glob(glob_path)
        if not paths:
            self.errors.append('(Disk attribs not found) - Cannot find attribs at {}'.format(glob_path))
        controls_overrides = {}
        for base in paths:
            for attr in os.listdir(base):
                path = base + "/" + attr
                if os.access(path, os.R_OK) and os.access(path, os.W_OK):
                    if attr not in self.controls_defaults:
                        self.errors.append('(Unknown attr) - Unknown default value for attr {}'.format(attr))
                    content = open(path).read().rstrip('\n')
                    if attr in controls_overrides and controls_overrides[attr] != content:
                        self.errors.append('(Each attr must have the same value for all disks in the targets) - '
                                           'Check attr {} on {}'.format(attr, path))
                    if attr not in self.controls_defaults or str(self.controls_defaults[attr]) != content:
                        controls_overrides[attr] = content
        return controls_overrides

    def add_portal(self, target_iqn, portal_name, ip):
        self.logger.debug('Adding portal %s / %s / %s', target_iqn, portal_name, ip)
        now = CephIscsiConfig._get_time()
        if portal_name not in self.config['gateways']:
            self.config['gateways'][portal_name] = {
                'active_luns': 0,
                'created': now
            }
        target_config = self.config['targets'][target_iqn]
        if 'ip_list' not in target_config:
            target_config['ip_list'] = []
        if portal_name not in target_config['portals']:
            target_config['portals'][portal_name] = {
                'created': now,
                'gateway_ip_list': [],
                'inactive_portal_ips': [],
                'portal_ip_address': ip,
                'tpgs': 0
            }
        target_config['ip_list'].append(ip)
        for portal_name, portal_config in target_config['portals'].items():
            portal_config['gateway_ip_list'] = target_config['ip_list']
            inactive_portal_ips = list(portal_config['gateway_ip_list'])
            inactive_portal_ips.remove(portal_config['portal_ip_address'])
            portal_config['inactive_portal_ips'] = inactive_portal_ips
            portal_config['tpgs'] = len(target_config['ip_list'])

    def _get_owner(self, target_iqn):
        target_config = self.config['targets'][target_iqn]
        owner = None
        for portal_name in target_config['portals'].keys():
            gateways_config = self.config['gateways']
            if owner is None or gateways_config[portal_name]['active_luns'] < gateways_config[owner]['active_luns']:
                owner = portal_name
        return owner

    def add_disk(self, target_iqn, pool, image, wwn):
        self.logger.debug('Adding disk %s / %s / %s / %s', target_iqn, pool, image, wwn)
        now = CephIscsiConfig._get_time()
        disk_id = '{}.{}'.format(pool, image)
        if disk_id in self.config['disks']:
            if disk_id not in self.config['targets'][target_iqn]['disks']:
                raise Exception("Disk {} cannot be exported by multiple targets".format(disk_id))
            return
        owner = self._get_owner(target_iqn)
        self.config['disks'][disk_id] = {
            'controls': self._get_controls(pool, image),
            'created': now,
            'image': image,
            'owner': owner,
            'pool': pool,
            'pool_id': CephIscsiConfig._get_pool_id(pool),
            'wwn': wwn
        }
        self.config['targets'][target_iqn]['disks'].append(disk_id)
        self.config['gateways'][owner]['active_luns'] += 1

    def add_client(self, target_iqn, client_iqn):
        self.logger.debug('Adding client %s / %s', target_iqn, client_iqn)
        target_config = self.config['targets'][target_iqn]
        target_config['clients'][client_iqn] = {
            'auth': {
                'chap': '',
                'chap_mutual': ''
            },
            'luns': {},
            'group_name': ''
        }

    def add_client_auth(self, target_iqn, client_iqn, userid, password, userid_mutual, password_mutual):
        self.logger.debug('Adding client lun %s / %s / %s / %s / %s / %s', target_iqn, client_iqn, userid, password, userid_mutual, password_mutual)
        client_config = self.config['targets'][target_iqn]['clients'][client_iqn]
        if userid and password:
            client_config['auth']['chap'] = '{}/{}'.format(userid, password)
        if userid_mutual and password_mutual:
            client_config['auth']['chap_mutual'] = '{}/{}'.format(userid_mutual, password_mutual)

    def add_client_lun(self, target_iqn, client_iqn, pool, image, lun_id):
        self.logger.debug('Adding client lun %s / %s / %s / %s / %s', target_iqn, client_iqn, pool, image, lun_id)
        client_config = self.config['targets'][target_iqn]['clients'][client_iqn]
        disk_id = '{}.{}'.format(pool, image)
        client_config['luns'][disk_id] = {
            'lun_id': lun_id
        }

    def add_discovery_auth(self, userid, password, userid_mutual, password_mutual):
        self.logger.debug('Adding discovery auth %s / %s / %s / %s', userid, password, userid_mutual, password_mutual)
        if userid and password:
            self.config['discovery_auth']['chap'] = '{}/{}'.format(userid, password)
        if userid_mutual and password_mutual:
            self.config['discovery_auth']['chap_mutual'] = '{}/{}'.format(userid_mutual, password_mutual)

    def persist_config(self):
        pprint = self.pprinter.pformat(self.config)
        self.logger.info('Generated config:\n%s', pprint)
        if self.errors:
            errors_str = ''
            for error in self.errors:
                errors_str += '\n    - {}'.format(error)
            raise Exception('ceph-iscsi config not persisted. Check the following errors:{}'.format(errors_str))
        else:
            # TODO - save config into rados
            pass


def main(logger):
    lio_root = RTSRoot()
    ceph_iscsi_config = CephIscsiConfig(logger)
    lrbd_config = LrbdConfig()
    discovery_auth_path = '{}/{}/{}'.format('/sys/kernel/config/target',
                                            'iscsi',
                                            'discovery_auth')
    userid = open(discovery_auth_path + "/userid").read().rstrip('\n')
    password = open(discovery_auth_path + "/password").read().rstrip('\n')
    userid_mutual = open(discovery_auth_path + "/userid_mutual").read().rstrip('\n')
    password_mutual = open(discovery_auth_path + "/password_mutual").read().rstrip('\n')
    ceph_iscsi_config.add_discovery_auth(userid, password, userid_mutual, password_mutual)
    for target in lio_root.targets:
        ceph_iscsi_config.add_target(target.wwn)
        # TODO - target controls
        for tpg in target.tpgs:
            logger.info('Processing tpg - %s', tpg)
            for network_portal in tpg.network_portals:
                portal_name = lrbd_config.get_portal_name(network_portal.ip_address)
                ceph_iscsi_config.add_portal(target.wwn, portal_name, network_portal.ip_address)
            disks_by_lun = {}
            for lun in tpg.luns:
                udev_path_list = lun.storage_object.udev_path.split('/')
                pool = udev_path_list[len(udev_path_list) - 2]
                image = udev_path_list[len(udev_path_list) - 1]
                disks_by_lun[lun.lun] = (pool, image)
                ceph_iscsi_config.add_disk(target.wwn, pool, image, lun.storage_object.wwn)
            for node_acl in tpg.node_acls:
                ceph_iscsi_config.add_client(target.wwn, node_acl.node_wwn)
                userid = node_acl.get_auth_attr('userid')
                password = node_acl.get_auth_attr('password')
                userid_mutual = node_acl.get_auth_attr('userid_mutual')
                password_mutual = node_acl.get_auth_attr('password_mutual')
                # TODO - check if auth is enabled
                # TODO - no auth
                ceph_iscsi_config.add_client_auth(target.wwn, node_acl.node_wwn, userid, password, userid_mutual, password_mutual)
                for mapped_lun in node_acl.mapped_luns:
                    disk = disks_by_lun[mapped_lun.mapped_lun]
                    ceph_iscsi_config.add_client_lun(target.wwn, node_acl.node_wwn, disk[0], disk[1], mapped_lun.mapped_lun)
    ceph_iscsi_config.persist_config()

if __name__ == "__main__":
    logger = logging.getLogger('lrbd-to-ceph-iscsi')
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler('/var/log/lrbd-to-ceph-iscsi.log')
    file_format = logging.Formatter("%(asctime)s [%(levelname)8s] - %(message)s")
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    main(logger)

