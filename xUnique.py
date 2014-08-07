#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This software is licensed under the Apache 2 license, quoted below.

Copyright 2014 Xiao Wang <wangxiao8611@gmail.com, http://fclef.wordpress.com/about>

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
from __future__ import print_function
from subprocess import (check_output as sp_co, check_call as sp_cc)
from os import path, unlink, rename
from hashlib import md5 as hl_md5
from json import (loads as json_loads, dump as json_dump)
from urllib import urlretrieve
from fileinput import (input as fi_input, close as fi_close)
from re import compile as re_compile
from sys import (argv as sys_argv, getfilesystemencoding as sys_get_fs_encoding)
from collections import deque
from filecmp import cmp as filecmp_cmp
from optparse import OptionParser


md5_hex = lambda a_str: hl_md5(a_str.encode('utf-8')).hexdigest().upper()


class XUnique(object):
    def __init__(self, target_path, verbose=False):
        # check project path
        abs_target_path = path.abspath(target_path)
        if not path.exists(abs_target_path):
            raise SystemExit('Path "{!r}" does not exist!'.format(abs_target_path))
        elif abs_target_path.endswith('xcodeproj'):
            self.xcodeproj_path = abs_target_path
            self.xcode_pbxproj_path = path.join(abs_target_path, 'project.pbxproj')
        elif abs_target_path.endswith('project.pbxproj'):
            self.xcode_pbxproj_path = abs_target_path
            self.xcodeproj_path = path.split(self.xcode_pbxproj_path)[0]
        else:
            raise SystemExit("Path must be dir '.xcodeproj' or file 'project.pbxproj'")
        self.verbose = verbose
        self.vprint = print if self.verbose else lambda *a, **k: None
        self.proj_root = path.basename(self.xcodeproj_path)  # example MyProject.xpbproj
        self.proj_json = self.pbxproj_to_json()
        self.nodes = self.proj_json['objects']
        self.root_hex = self.proj_json['rootObject']
        self.root_node = self.nodes[self.root_hex]
        self.main_group_hex = self.root_node['mainGroup']
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
        json_unicode_str = sp_co(pbproj_to_json_cmd).decode(sys_get_fs_encoding())
        return json_loads(json_unicode_str)

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
        """"""
        self.unique_project()
        self.sort_pbxproj()

    def unique_project(self):
        """iterate all nodes in pbxproj file:

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
        if self.verbose:
            debug_result_file_path = path.join(self.xcodeproj_path, 'debug_result.json')
            with open(debug_result_file_path, 'w') as debug_result_file:
                json_dump(self.__result, debug_result_file)
            self.vprint("result json file has been written to '{}'".format(debug_result_file_path))
        self.replace_uuids_with_file()


    def replace_uuids_with_file(self):
        self.vprint('replace UUIDs and remove unused UUIDs')
        uuid_ptn = re_compile('(?<=\s)[0-9A-F]{24}(?=[\s;])')
        for line in fi_input(self.xcode_pbxproj_path, backup='.bak', inplace=1):
            # project.pbxproj is an utf-8 encoded file
            line = line.decode('utf-8')
            uuid_list = uuid_ptn.findall(line)
            if not uuid_list:
                print(line.encode('utf-8'), end='')
            else:
                new_line = line
                # remove line with non-existing element
                if self.__result.get('to_be_removed') and any(
                        i for i in uuid_list if i in self.__result['to_be_removed']):
                    continue
                else:
                    for uuid in uuid_list:
                        new_line = new_line.replace(uuid, self.__result[uuid]['new_key'])
                    print(new_line.encode('utf-8'), end='')
        fi_close()
        tmp_path = self.xcode_pbxproj_path + '.bak'
        if filecmp_cmp(self.xcode_pbxproj_path, tmp_path, shallow=False):
            unlink(self.xcode_pbxproj_path)
            rename(tmp_path, self.xcode_pbxproj_path)
            print('Ignore uniquify, no changes made to', self.xcode_pbxproj_path)
        else:
            unlink(tmp_path)
            print('Uniquify done')

    def sort_pbxproj_pl(self):
        """
        deprecated, use pure python method sort_pbxproj() below

        https://github.com/truebit/webkit/commits/master/Tools/Scripts/sort-Xcode-project-file

        my modified version which supports:
        1. sort PBXFileReference and PBXBuildFile sections
        2. avoid creating new file if no changes made
        """
        sort_script_path = path.join(path.dirname(path.abspath(__file__)), 'sort-Xcode-project-file-mod2.pl')
        if not path.exists(sort_script_path):
            self.vprint('downloading sort-Xcode-project-file')
            f_path, http_msgs = urlretrieve(
                'https://raw.githubusercontent.com/truebit/webkit/master/Tools/Scripts/sort-Xcode-project-file',
                filename=sort_script_path)
            if int(http_msgs['content-length']) < 1000:  # current is 6430
                raise SystemExit(
                    'Cannot download script file from "https://raw.githubusercontent.com/truebit/webkit/master/Tools/Scripts/sort-Xcode-project-file"')
            for line in fi_input(sort_script_path, inplace=1, backup='.bak'):
                print(line.replace('{24}', '{32}'), end='')
            fi_close()
            unlink(sort_script_path + '.bak')
        self.vprint('sort project.xpbproj file')
        sp_cc(['perl', sort_script_path, self.xcode_pbxproj_path])

    def sort_pbxproj(self):
        self.vprint('sort project.xpbproj file')
        uuid_chars = len(self.main_group_hex)
        lines = []
        files_start_ptn = re_compile('^(\s*)files = \(\s*$')
        files_key_ptn = re_compile('(?<=[A-F0-9]{{{}}} \/\* ).+?(?= in )'.format(uuid_chars))
        fc_end_ptn = '\);'
        files_flag = False
        children_start_ptn = re_compile('^(\s*)children = \(\s*$')
        children_pbx_key_ptn = re_compile('(?<=[A-F0-9]{{{}}} \/\* ).+?(?= \*\/)'.format(uuid_chars))
        child_flag = False
        pbx_start_ptn = re_compile('^.*Begin (PBXBuildFile|PBXFileReference) section.*$')
        pbx_end_ptn = ('^.*End ', ' section.*$')
        pbx_flag = False
        last_two = deque([])

        def file_dir_cmp(x, y):
            if '.' in x:
                if '.' in y:
                    return cmp(x, y)
                else:
                    return 1
            else:
                if '.' in y:
                    return -1
                else:
                    return cmp(x, y)

        for line in fi_input(self.xcode_pbxproj_path, backup='.bak', inplace=1):
            # project.pbxproj is an utf-8 encoded file
            line = line.decode('utf-8')
            last_two.append(line)
            if len(last_two) > 2:
                last_two.popleft()
            # files search and sort
            files_match = files_start_ptn.search(line)
            if files_match:
                print(line, end='')
                files_flag = True
                if isinstance(fc_end_ptn, unicode):
                    fc_end_ptn = re_compile(files_match.group(1) + fc_end_ptn)
            if files_flag:
                if fc_end_ptn.search(line):
                    if lines:
                        lines.sort(key=lambda file_str: files_key_ptn.search(file_str).group())
                        print(''.join(lines).encode('utf-8'), end='')
                        lines = []
                    files_flag = False
                    fc_end_ptn = '\);'
                elif files_key_ptn.search(line):
                    lines.append(line)
            # children search and sort
            children_match = children_start_ptn.search(line)
            if children_match:
                print(line, end='')
                child_flag = True
                if isinstance(fc_end_ptn, unicode):
                    fc_end_ptn = re_compile(children_match.group(1) + fc_end_ptn)
            if child_flag:
                if fc_end_ptn.search(line):
                    if lines:
                        if self.main_group_hex not in last_two[0]:
                            lines.sort(key=lambda file_str: children_pbx_key_ptn.search(file_str).group(),
                                       cmp=file_dir_cmp)
                        print(''.join(lines).encode('utf-8'), end='')
                        lines = []
                    child_flag = False
                    fc_end_ptn = '\);'
                elif children_pbx_key_ptn.search(line):
                    lines.append(line)
            # PBX search and sort
            pbx_match = pbx_start_ptn.search(line)
            if pbx_match:
                print(line, end='')
                pbx_flag = True
                if isinstance(pbx_end_ptn, tuple):
                    pbx_end_ptn = re_compile(pbx_match.group(1).join(pbx_end_ptn))
            if pbx_flag:
                if pbx_end_ptn.search(line):
                    if lines:
                        lines.sort(key=lambda file_str: children_pbx_key_ptn.search(file_str).group())
                        print(''.join(lines).encode('utf-8'), end='')
                        lines = []
                    pbx_flag = False
                    pbx_end_ptn = ('^.*End ', ' section.*')
                elif children_pbx_key_ptn.search(line):
                    lines.append(line)
            # normal output
            if not (files_flag or child_flag or pbx_flag):
                print(line, end='')
        fi_close()
        tmp_path = self.xcode_pbxproj_path + '.bak'
        if filecmp_cmp(self.xcode_pbxproj_path, tmp_path, shallow=False):
            unlink(self.xcode_pbxproj_path)
            rename(tmp_path, self.xcode_pbxproj_path)
            print('Ignore sort, no changes made to', self.xcode_pbxproj_path)
        else:
            unlink(tmp_path)
            print('Sort done')

    def __unique_project(self, project_hex):
        '''PBXProject. It is root itself, no parents to it'''
        self.vprint('uniquify PBXProject')
        self.vprint('uniquify PBXGroup and PBXFileRef')
        self.__unique_group_or_ref(project_hex, self.main_group_hex)
        self.vprint('uniquify XCConfigurationList')
        bcl_hex = self.root_node['buildConfigurationList']
        self.__unique_build_configuration_list(project_hex, bcl_hex)
        subprojects_list = self.root_node.get('projectReferences')
        if subprojects_list:
            self.vprint('uniquify Subprojects')
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
        self.vprint('uniquify XCConfiguration')
        for build_configuration_hex in build_configuration_list_node['buildConfigurations']:
            self.__unique_build_configuration(build_configuration_list_hex, build_configuration_hex)

    def __unique_build_configuration(self, parent_hex, build_configuration_hex):
        '''XCBuildConfiguration'''
        cur_path_key = 'name'
        self.__set_to_result(parent_hex, build_configuration_hex, cur_path_key)

    def __unique_target(self, parent_hex, target_hex):
        '''PBXNativeTarget'''
        self.vprint('uniquify PBXNativeTarget')
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
        self.vprint('uniquify PBXContainerItemProxy')
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
        self.vprint('uniquify PBXSourcesBuildPhase, PBXFrameworksBuildPhase and PBXResourcesBuildPhase')
        current_node = self.nodes[build_phase_hex]
        # no useful key, use its isa value
        cur_path_key = current_node['isa']
        self.__set_to_result(parent_hex, build_phase_hex, cur_path_key)
        self.vprint('uniquify PBXBuildFile')
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


def main(sys_args):
    usage = "usage: %prog [-v|-verbose][-u|--unique][-s|--sort] path/to/Project.xcodeproj"
    description = "By default, without any option, xUnique uniquify and sort the project file."
    parser = OptionParser(usage=usage, description=description)
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="output verbose messages. default is False.")
    parser.add_option("-u", "--unique", action="store_true", dest="unique_bool", default=False,
                      help="uniquify the project file. default is False.")
    parser.add_option("-s", "--sort", action="store_true", dest="sort_bool", default=False,
                      help="sort the project file. default is False.")
    (options, args) = parser.parse_args(sys_args[1:])
    if len(args) < 1:
        parser.print_help()
        raise SystemExit("xUnique requires at least one positional argument: relative/absolute path to xcodeproj.")
    xcode_proj_path = args[0].decode(sys_get_fs_encoding())
    xunique = XUnique(xcode_proj_path, options.verbose)
    if not (options.unique_bool or options.sort_bool):
        print("Uniquify and Sort")
        xunique.unique_pbxproj()
        print("Uniquify and Sort done")
    else:
        if options.unique_bool:
            print('Uniquify...')
            xunique.unique_project()
        if options.sort_bool:
            print('Sort...')
            xunique.sort_pbxproj()


if __name__ == '__main__':
    main(sys_argv)
