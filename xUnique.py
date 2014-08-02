#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This software is licensed under the Apache 2 license, quoted below.

Copyright 2014 Wang Xiao <wangxiao8611@gmail.com, http://fclef.wordpress.com/about>

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License. You may obtain a copy of
the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
"""

from __future__ import unicode_literals
from subprocess import (check_output as sp_co, check_call as sp_cc)
from os import path, unlink
from hashlib import md5 as hl_md5
import json
from urllib import urlretrieve
from fileinput import (input as fi_input, close as fi_close)
from re import compile as re_compile
from sys import argv as sys_argv

md5_hex = lambda a_str: hl_md5(a_str.encode('utf-8')).hexdigest().upper()


class XUnique(object):
    def __init__(self, xcodeproj_path):
        # check project path
        abs_xcodeproj_path = path.abspath(xcodeproj_path)
        if not path.exists(abs_xcodeproj_path):
            raise SystemExit('Path "{!r}" does not exist!'.format(abs_xcodeproj_path))
        elif xcodeproj_path.endswith(('xcodeproj','xcodeproj/')):
            self.xcodeproj_path = abs_xcodeproj_path
            self.xcode_pbxproj_path = path.join(abs_xcodeproj_path, 'project.pbxproj')
        elif abs_xcodeproj_path.endswith('project.pbxproj'):
            self.xcode_pbxproj_path = abs_xcodeproj_path
            self.xcodeproj_path = path.split(self.xcode_pbxproj_path)[0]
        else:
            raise SystemExit("Path must be dir '.xcodeproj' or file 'project.pbxproj'")
        self.proj_root = path.basename(self.xcodeproj_path)  # example MyProject.xpbproj
        self.proj_json = self.pbxproj_to_json()
        self.nodes = self.proj_json['objects']
        self.root_hex = self.proj_json['rootObject']
        self.root_node = self.nodes[self.root_hex]
        self.__result = {}
        # initialize root content
        self.__result.update(
            {
                self.root_hex: {'path': self.proj_root,
                                'new_key': md5_hex(self.proj_root),
                                'type': self.root_node['isa']
                }
            })

    def pbxproj_to_json(self):
        pbproj_to_json_cmd = ['plutil', '-convert', 'json', '-o', '-', self.xcode_pbxproj_path]
        json_str = sp_co(pbproj_to_json_cmd)
        return json.loads(json_str)

    def __set_to_result(self, parent_hex, current_hex, current_path_key):
        current_node = self.nodes[current_hex]
        if isinstance(current_path_key, (list, tuple)):
            current_path = '/'.join([current_node[i] for i in current_path_key])
        elif isinstance(current_path_key, (basestring, unicode)):
            if current_path_key in current_node.keys():
                current_path = current_node[current_path_key]
            else:
                current_path = current_path_key
        else:
            raise KeyError('current_path_key must be list/tuple/string')
        cur_abs_path = '{}/{}'.format(self.__result[parent_hex]['path'], current_path)
        self.__result.update({
            current_hex: {'path': cur_abs_path,
                          'new_key': md5_hex(cur_abs_path),
                          'type': self.nodes[current_hex]['isa']
            }
        })

    def unique_pbxproj(self):
        """
        iterate all nodes in pbxproj file:

        PBXProject
        XCConfigurationList
        PBXNativeTarget
        PBXTargetDependency
        PBXContainerItemProxy
        XCBuildConfiguration
        PBXSourcesBuildPhase
        PBXFrameworksBuildPhase
        PBXResourcesBuildPhase
        PBXBuildFile
        PBXReferenceProxy
        PBXFileReference
        PBXGroup
        PBXVariantGroup
        """
        self.__unique_project(self.root_hex)
        # with open(path.join(self.xcodeproj_path),'w') as result_file:
        # json.dump(self.__result,result_file)
        self.replace_uuids_with_file()
        self.sort_pbxproj()

    def replace_uuids_with_file(self):
        print 'replace UUIDs and remove unused UUIDs'
        uuid_ptn = re_compile('(?<=\s)[0-9A-F]{24}(?=[\s;])')
        for line in fi_input(self.xcode_pbxproj_path, backup='.bak', inplace=1):
            uuid_list = uuid_ptn.findall(line)
            if not uuid_list:
                print line,
            else:
                new_line = line
                # remove line with non-existing element
                if self.__result.get('to_be_removed') and any(
                        i for i in uuid_list if i in self.__result['to_be_removed']):
                    continue
                else:
                    for uuid in uuid_list:
                        new_line = new_line.replace(uuid, self.__result[uuid]['new_key'])
                    print new_line,
        fi_close()
        unlink(self.xcode_pbxproj_path + '.bak')

    def sort_pbxproj(self):
        '''https://github.com/WebKit/webkit/blob/master/Tools/Scripts/sort-Xcode-project-file'''
        sort_script_path = path.join(path.dirname(path.abspath(__file__)), 'sort-Xcode-project-file-v32.pl')
        if not path.exists(sort_script_path):
            print 'downloading sort-Xcode-project-file'
            f_path, http_msgs = urlretrieve(
                'https://raw.githubusercontent.com/WebKit/webkit/master/Tools/Scripts/sort-Xcode-project-file',
                filename=sort_script_path)
            if int(http_msgs['content-length']) < 1000:  # current is 5850
                raise SystemExit(
                    'Cannot download script file from "https://raw.githubusercontent.com/WebKit/webkit/master/Tools/Scripts/sort-Xcode-project-file"')
            for line in fi_input(sort_script_path, inplace=1, backup='.bak'):
                print line.replace('{24}', '{32}'),
            fi_close()
            unlink(sort_script_path + '.bak')
        print 'sort project.xpbproj file'
        sp_cc(['perl', sort_script_path, self.xcode_pbxproj_path])

    def __unique_project(self, project_hex):
        '''PBXProject. It is root itself, no parents to it'''
        print 'uniquify PBXProject'
        print 'uniquify PBXGroup and PBXFileRef'
        main_group_hex = self.root_node['mainGroup']
        self.__unique_group_or_ref(project_hex, main_group_hex)
        print 'uniquify XCConfigurationList'
        bcl_hex = self.root_node['buildConfigurationList']
        self.__unique_build_configuration_list(project_hex, bcl_hex)
        subprojects_list = self.root_node.get('projectReferences')
        if subprojects_list:
            print 'uniquify Subprojects'
            for subproject_dict in subprojects_list:
                product_group_hex = subproject_dict['ProductGroup']
                project_ref_parent_hex = subproject_dict['ProjectRef']
                self.__unique_group_or_ref(project_ref_parent_hex, product_group_hex)
        targets_list = self.root_node['targets']
        for target_hex in targets_list:
            self.__unique_target(project_hex, target_hex)

    def __unique_build_configuration_list(self, parent_hex, build_configuration_list_hex):
        '''XCConfigurationList'''
        cur_path_key = 'defaultConfigurationName'
        self.__set_to_result(parent_hex, build_configuration_list_hex, cur_path_key)
        build_configuration_list_node = self.nodes[build_configuration_list_hex]
        print 'uniquify XCConfiguration'
        for build_configuration_hex in build_configuration_list_node['buildConfigurations']:
            self.__unique_build_configuration(build_configuration_list_hex, build_configuration_hex)

    def __unique_build_configuration(self, parent_hex, build_configuration_hex):
        '''XCBuildConfiguration'''
        cur_path_key = 'name'
        self.__set_to_result(parent_hex, build_configuration_hex, cur_path_key)

    def __unique_target(self, parent_hex, target_hex):
        '''PBXNativeTarget'''
        print 'uniquify PBXNativeTarget'
        cur_path_key = ('productName', 'name')
        self.__set_to_result(parent_hex, target_hex, cur_path_key)
        current_node = self.nodes[target_hex]
        bcl_hex = current_node['buildConfigurationList']
        self.__unique_build_configuration_list(target_hex, bcl_hex)
        dependencies_list = current_node.get('dependencies')
        if dependencies_list:
            for dependency_hex in dependencies_list:
                self.__unique_target_dependency(target_hex, dependency_hex)
        build_phases_list = current_node['buildPhases']
        for build_phase_hex in build_phases_list:
            self.__unique_build_phase(target_hex, build_phase_hex)

    def __unique_target_dependency(self, parent_hex, target_dependency_hex):
        '''PBXTargetDependency'''
        self.__set_to_result(parent_hex, target_dependency_hex, 'name')
        self.__unique_container_item_proxy(target_dependency_hex, self.nodes[target_dependency_hex]['targetProxy'])

    def __unique_container_item_proxy(self, parent_hex, container_item_proxy_hex):
        '''PBXContainerItemProxy'''
        print 'uniquify PBXContainerItemProxy'
        self.__set_to_result(parent_hex, container_item_proxy_hex, 'remoteInfo')
        cur_path = self.__result[container_item_proxy_hex]['path']
        current_node = self.nodes[container_item_proxy_hex]
        # re-calculate remoteGlobalIDString to a new length 32 MD5 digest
        remote_global_id_hex = current_node['remoteGlobalIDString']
        portal_hex = current_node['containerPortal']
        portal_path = self.__result[portal_hex]['path']
        new_rg_id_path = '{}+{}'.format(cur_path, portal_path)
        self.__result.update({
            remote_global_id_hex: {'path': new_rg_id_path,
                                   'new_key': md5_hex(new_rg_id_path),
                                   'type': '{}#{}'.format(self.nodes[container_item_proxy_hex]['isa'],
                                                          'remoteGlobalIDString')
            }
        })

    def __unique_build_phase(self, parent_hex, build_phase_hex):
        '''PBXSourcesBuildPhase PBXFrameworksBuildPhase PBXResourcesBuildPhase PBXCopyFilesBuildPhase'''
        print 'uniquify PBXSourcesBuildPhase, PBXFrameworksBuildPhase and PBXResourcesBuildPhase'
        current_node = self.nodes[build_phase_hex]
        # no useful key, use its isa value
        cur_path_key = current_node['isa']
        self.__set_to_result(parent_hex, build_phase_hex, cur_path_key)
        print 'uniquify PBXBuildFile'
        for build_file_hex in current_node['files']:
            self.__unique_build_file(build_phase_hex, build_file_hex)

    def __unique_group_or_ref(self, parent_hex, group_ref_hex):
        '''PBXFileReference PBXGroup PBXVariantGroup PBXReferenceProxy'''
        current_hex = group_ref_hex
        if self.nodes[current_hex].get('name'):
            cur_path_key = 'name'
        elif self.nodes[current_hex].get('path'):
            cur_path_key = 'path'
        else:
            # root PBXGroup has neither path nor name, give a new name 'PBXRootGroup'
            cur_path_key = 'PBXRootGroup'
        self.__set_to_result(parent_hex, current_hex, cur_path_key)
        if self.nodes[current_hex].get('children'):
            for child_hex in self.nodes[current_hex]['children']:
                self.__unique_group_or_ref(current_hex, child_hex)
        elif self.nodes[current_hex]['isa'] == 'PBXReferenceProxy':
            self.__unique_container_item_proxy(parent_hex, self.nodes[current_hex]['remoteRef'])

    def __unique_build_file(self, parent_hex, build_file_hex):
        '''PBXBuildFile'''
        current_node = self.nodes[build_file_hex]
        file_ref_hex = current_node['fileRef']
        if self.__result.get(file_ref_hex):
            cur_path_key = self.__result[file_ref_hex]['path']
            self.__set_to_result(parent_hex, build_file_hex, cur_path_key)
        else:
            self.__result.setdefault('to_be_removed', []).extend((build_file_hex, file_ref_hex))


if __name__ == '__main__':
    if len(sys_argv) != 2:
        raise SystemExit('usage: xUnique.py path/to/Project.xcodeproj')
    else:
        xcode_proj_path = sys_argv[1]
        xunique = XUnique(xcode_proj_path)
        xunique.unique_pbxproj()
