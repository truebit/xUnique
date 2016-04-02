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
from subprocess import (check_output as sp_co, CalledProcessError)
from os import path, unlink, rename
from hashlib import md5 as hl_md5
from json import (loads as json_loads, dump as json_dump)
from fileinput import (input as fi_input, close as fi_close)
from re import compile as re_compile
from sys import (argv as sys_argv, getfilesystemencoding as sys_get_fs_encoding)
from collections import deque
from filecmp import cmp as filecmp_cmp
from optparse import OptionParser


def construct_compatibility_layer():
    import sys
    if sys.version_info.major == 3:
        class SixPython3Impl(object):
            PY2 = False
            PY3 = True
            text_type = str
            string_types = (str,)

        return SixPython3Impl
    elif sys.version_info.major == 2:
        class SixPython2Impl(object):
            PY2 = True
            PY3 = False
            text_type = unicode
            string_types = (basestring,)

        return SixPython2Impl
    else:
        raise RuntimeError("unsupported python version")


six = construct_compatibility_layer()

md5_hex = lambda a_str: hl_md5(a_str.encode('utf-8')).hexdigest().upper()
if six.PY2:
    print_ng = lambda *args, **kwargs: print(*[six.text_type(i).encode(sys_get_fs_encoding()) for i in args], **kwargs)
    output_u8line = lambda *args: print(*[six.text_type(i).encode('utf-8') for i in args], end='')
elif six.PY3:
    print_ng = lambda *args, **kwargs: print(*args, **kwargs)
    output_u8line = lambda *args: print(*args, end='')


def decoded_string(string, encoding=None):
    if isinstance(string, six.text_type):
        return string
    return string.decode(encoding or sys_get_fs_encoding())


def warning_print(*args, **kwargs):
    new_args = list(args)
    new_args[0] = '\x1B[33m{}'.format(new_args[0])
    new_args[-1] = '{}\x1B[0m'.format(new_args[-1])
    print_ng(*new_args, **kwargs)


def success_print(*args, **kwargs):
    new_args = list(args)
    new_args[0] = '\x1B[32m{}'.format(new_args[0])
    new_args[-1] = '{}\x1B[0m'.format(new_args[-1])
    print_ng(*new_args, **kwargs)


class XUnique(object):
    def __init__(self, target_path, verbose=False):
        # check project path
        abs_target_path = path.abspath(target_path)
        if not path.exists(abs_target_path):
            raise XUniqueExit('Path "{}" not found!'.format(abs_target_path))
        elif abs_target_path.endswith('xcodeproj'):
            self.xcodeproj_path = abs_target_path
            self.xcode_pbxproj_path = path.join(abs_target_path, 'project.pbxproj')
        elif abs_target_path.endswith('project.pbxproj'):
            self.xcode_pbxproj_path = abs_target_path
            self.xcodeproj_path = path.dirname(self.xcode_pbxproj_path)
        else:
            raise XUniqueExit("Path must be dir '.xcodeproj' or file 'project.pbxproj'")
        self.verbose = verbose
        self.vprint = print if self.verbose else lambda *a, **k: None
        self.proj_root = self.get_proj_root()
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
        self._is_modified = False

    @property
    def is_modified(self):
        return self._is_modified

    def pbxproj_to_json(self):
        pbproj_to_json_cmd = ['plutil', '-convert', 'json', '-o', '-', self.xcode_pbxproj_path]
        try:
            json_unicode_str = decoded_string(sp_co(pbproj_to_json_cmd))
            return json_loads(json_unicode_str)
        except CalledProcessError as cpe:
            raise XUniqueExit("""{}
Please check:
1. You have installed Xcode Command Line Tools and command 'plutil' could be found in $PATH;
2. The project file is not broken, such like merge conflicts, incomplete content due to xUnique failure. """.format(
                cpe.output))

    def __set_to_result(self, parent_hex, current_hex, current_path_key):
        current_node = self.nodes[current_hex]
        isa_type = current_node['isa']
        if isinstance(current_path_key, (list, tuple)):
            current_path = '/'.join([str(current_node[i]) for i in current_path_key])
        elif isinstance(current_path_key, six.string_types):
            if current_path_key in current_node.keys():
                current_path = current_node[current_path_key]
            else:
                current_path = current_path_key
        else:
            raise KeyError('current_path_key must be list/tuple/string')
        cur_abs_path = '{}/{}'.format(self.__result[parent_hex]['path'], current_path)
        new_key = md5_hex(cur_abs_path)
        self.__result.update({
            current_hex: {'path': '{}[{}]'.format(isa_type, cur_abs_path),
                          'new_key': new_key,
                          'type': isa_type
                          }
        })
        return new_key

    def get_proj_root(self):
        """PBXProject name,the root node"""
        pbxproject_ptn = re_compile('(?<=PBXProject ").*(?=")')
        with open(self.xcode_pbxproj_path) as pbxproj_file:
            for line in pbxproj_file:
                # project.pbxproj is an utf-8 encoded file
                line = decoded_string(line, 'utf-8')
                result = pbxproject_ptn.search(line)
                if result:
                    # Backward compatibility using suffix
                    return '{}.xcodeproj'.format(result.group())
        raise XUniqueExit("File 'project.pbxproj' is broken. Cannot find PBXProject name.")

    def unique_project(self):
        """iterate all nodes in pbxproj file:

        PBXProject
        XCConfigurationList
        PBXNativeTarget
        PBXTargetDependency
        PBXContainerItemProxy
        XCBuildConfiguration
        PBX*BuildPhase
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
            warning_print("Debug result json file has been written to '", debug_result_file_path, sep='')
        self.substitute_old_keys()

    def substitute_old_keys(self):
        self.vprint('replace UUIDs and remove unused UUIDs')
        key_ptn = re_compile('(?<=\s)([0-9A-Z]{24}|[0-9A-F]{32})(?=[\s;])')
        removed_lines = []
        for line in fi_input(self.xcode_pbxproj_path, backup='.ubak', inplace=1):
            # project.pbxproj is an utf-8 encoded file
            line = decoded_string(line, 'utf-8')
            key_list = key_ptn.findall(line)
            if not key_list:
                output_u8line(line)
            else:
                new_line = line
                # remove line with non-existing element
                if self.__result.get('to_be_removed') and any(
                        i for i in key_list if i in self.__result['to_be_removed']):
                    removed_lines.append(new_line)
                    continue
                # remove incorrect entry that somehow does not exist in project node tree
                elif not all(self.__result.get(uuid) for uuid in key_list):
                    removed_lines.append(new_line)
                    continue
                else:
                    for key in key_list:
                        new_key = self.__result[key]['new_key']
                        new_line = new_line.replace(key, new_key)
                    output_u8line(new_line)
        fi_close()
        tmp_path = self.xcode_pbxproj_path + '.ubak'
        if filecmp_cmp(self.xcode_pbxproj_path, tmp_path, shallow=False):
            unlink(self.xcode_pbxproj_path)
            rename(tmp_path, self.xcode_pbxproj_path)
            warning_print('Ignore uniquify, no changes made to "', self.xcode_pbxproj_path, sep='')
        else:
            unlink(tmp_path)
            self._is_modified = True
            success_print('Uniquify done')
            if self.__result.get('uniquify_warning'):
                warning_print(*self.__result['uniquify_warning'])
            if removed_lines:
                warning_print('Following lines were deleted because of invalid format or no longer being used:')
                print_ng(*removed_lines, end='')

    def sort_pbxproj(self, sort_pbx_by_file_name=False):
        self.vprint('sort project.xpbproj file')
        lines = []
        removed_lines = []
        files_start_ptn = re_compile('^(\s*)files = \(\s*$')
        files_key_ptn = re_compile('((?<=[A-Z0-9]{24} \/\* )|(?<=[A-F0-9]{32} \/\* )).+?(?= in )')
        fc_end_ptn = '\);'
        files_flag = False
        children_start_ptn = re_compile('^(\s*)children = \(\s*$')
        children_pbx_key_ptn = re_compile('((?<=[A-Z0-9]{24} \/\* )|(?<=[A-F0-9]{32} \/\* )).+?(?= \*\/)')
        child_flag = False
        pbx_start_ptn = re_compile('^.*Begin (PBXBuildFile|PBXFileReference) section.*$')
        pbx_key_ptn = re_compile('^\s+(([A-Z0-9]{24})|([A-F0-9]{32}))(?= \/\*)')
        pbx_end_ptn = ('^.*End ', ' section.*$')
        pbx_flag = False
        last_two = deque([])

        def file_dir_order(x):
            x = children_pbx_key_ptn.search(x).group()
            return '.' in x, x

        for line in fi_input(self.xcode_pbxproj_path, backup='.sbak', inplace=1):
            # project.pbxproj is an utf-8 encoded file
            line = decoded_string(line, 'utf-8')
            last_two.append(line)
            if len(last_two) > 2:
                last_two.popleft()
            # files search and sort
            files_match = files_start_ptn.search(line)
            if files_match:
                output_u8line(line)
                files_flag = True
                if isinstance(fc_end_ptn, six.text_type):
                    fc_end_ptn = re_compile(files_match.group(1) + fc_end_ptn)
            if files_flag:
                if fc_end_ptn.search(line):
                    if lines:
                        lines.sort(key=lambda file_str: files_key_ptn.search(file_str).group())
                        output_u8line(''.join(lines))
                        lines = []
                    files_flag = False
                    fc_end_ptn = '\);'
                elif files_key_ptn.search(line):
                    if line in lines:
                        removed_lines.append(line)
                    else:
                        lines.append(line)
            # children search and sort
            children_match = children_start_ptn.search(line)
            if children_match:
                output_u8line(line)
                child_flag = True
                if isinstance(fc_end_ptn, six.text_type):
                    fc_end_ptn = re_compile(children_match.group(1) + fc_end_ptn)
            if child_flag:
                if fc_end_ptn.search(line):
                    if lines:
                        if self.main_group_hex not in last_two[0]:
                            lines.sort(key=file_dir_order)
                        output_u8line(''.join(lines))
                        lines = []
                    child_flag = False
                    fc_end_ptn = '\);'
                elif children_pbx_key_ptn.search(line):
                    if line in lines:
                        removed_lines.append(line)
                    else:
                        lines.append(line)
            # PBX search and sort
            pbx_match = pbx_start_ptn.search(line)
            if pbx_match:
                output_u8line(line)
                pbx_flag = True
                if isinstance(pbx_end_ptn, tuple):
                    pbx_end_ptn = re_compile(pbx_match.group(1).join(pbx_end_ptn))
            if pbx_flag:
                if pbx_end_ptn.search(line):
                    if lines:
                        if sort_pbx_by_file_name:
                            lines.sort(key=lambda file_str: children_pbx_key_ptn.search(file_str).group())
                        else:
                            lines.sort(key=lambda file_str: pbx_key_ptn.search(file_str).group(1))
                        output_u8line(''.join(lines))
                        lines = []
                    pbx_flag = False
                    pbx_end_ptn = ('^.*End ', ' section.*')
                elif children_pbx_key_ptn.search(line):
                    if line in lines:
                        removed_lines.append(line)
                    else:
                        lines.append(line)
            # normal output
            if not (files_flag or child_flag or pbx_flag):
                output_u8line(line)
        fi_close()
        tmp_path = self.xcode_pbxproj_path + '.sbak'
        if filecmp_cmp(self.xcode_pbxproj_path, tmp_path, shallow=False):
            unlink(self.xcode_pbxproj_path)
            rename(tmp_path, self.xcode_pbxproj_path)
            warning_print('Ignore sort, no changes made to "', self.xcode_pbxproj_path, sep='')
        else:
            unlink(tmp_path)
            self._is_modified = True
            success_print('Sort done')
            if removed_lines:
                warning_print('Following lines were deleted because of duplication:')
                print_ng(*removed_lines, end='')

    def __unique_project(self, project_hex):
        """PBXProject. It is root itself, no parents to it"""
        self.vprint('uniquify PBXProject')
        self.vprint('uniquify PBX*Group and PBX*Reference*')
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
        # workaround for PBXTargetDependency referring target that have not been iterated
        for target_hex in targets_list:
            cur_path_key = ('productName', 'name')
            self.__set_to_result(project_hex, target_hex, cur_path_key)
        for target_hex in targets_list:
            self.__unique_target(target_hex)

    def __unique_build_configuration_list(self, parent_hex, build_configuration_list_hex):
        """XCConfigurationList"""
        cur_path_key = 'defaultConfigurationName'
        self.__set_to_result(parent_hex, build_configuration_list_hex, cur_path_key)
        build_configuration_list_node = self.nodes[build_configuration_list_hex]
        self.vprint('uniquify XCConfiguration')
        for build_configuration_hex in build_configuration_list_node['buildConfigurations']:
            self.__unique_build_configuration(build_configuration_list_hex, build_configuration_hex)

    def __unique_build_configuration(self, parent_hex, build_configuration_hex):
        """XCBuildConfiguration"""
        cur_path_key = 'name'
        self.__set_to_result(parent_hex, build_configuration_hex, cur_path_key)

    def __unique_target(self, target_hex):
        """PBXNativeTarget PBXAggregateTarget"""
        self.vprint('uniquify PBX*Target')
        current_node = self.nodes[target_hex]
        bcl_hex = current_node['buildConfigurationList']
        self.__unique_build_configuration_list(target_hex, bcl_hex)
        dependencies_list = current_node.get('dependencies')
        if dependencies_list:
            self.vprint('uniquify PBXTargetDependency')
            for dependency_hex in dependencies_list:
                self.__unique_target_dependency(target_hex, dependency_hex)
        build_phases_list = current_node['buildPhases']
        for build_phase_hex in build_phases_list:
            self.__unique_build_phase(target_hex, build_phase_hex)
        build_rules_list = current_node.get('buildRules')
        if build_rules_list:
            for build_rule_hex in build_rules_list:
                self.__unique_build_rules(target_hex, build_rule_hex)

    def __unique_target_dependency(self, parent_hex, target_dependency_hex):
        """PBXTargetDependency"""
        target_hex = self.nodes[target_dependency_hex].get('target')
        if target_hex:
            self.__set_to_result(parent_hex, target_dependency_hex, self.__result[target_hex]['path'])
        else:
            self.__set_to_result(parent_hex, target_dependency_hex, 'name')
        self.__unique_container_item_proxy(target_dependency_hex, self.nodes[target_dependency_hex]['targetProxy'])

    def __unique_container_item_proxy(self, parent_hex, container_item_proxy_hex):
        """PBXContainerItemProxy"""
        self.vprint('uniquify PBXContainerItemProxy')
        new_container_item_proxy_hex = self.__set_to_result(parent_hex, container_item_proxy_hex, ('isa', 'remoteInfo'))
        cur_path = self.__result[container_item_proxy_hex]['path']
        current_node = self.nodes[container_item_proxy_hex]
        # re-calculate remoteGlobalIDString to a new length 32 MD5 digest
        remote_global_id_hex = current_node.get('remoteGlobalIDString')
        if not remote_global_id_hex:
            self.__result.setdefault('uniquify_warning', []).append(
                "PBXTargetDependency '{}' and its child PBXContainerItemProxy '{}' are not needed anymore, please remove their sections manually".format(
                    self.__result[parent_hex]['new_key'], new_container_item_proxy_hex))
        elif remote_global_id_hex not in self.__result.keys():
            portal_hex = current_node['containerPortal']
            portal_result_hex = self.__result.get(portal_hex)
            if not portal_result_hex:
                self.__result.setdefault('uniquify_warning', []).append(
                    "PBXTargetDependency '{}' and its child PBXContainerItemProxy '{}' are not needed anymore, please remove their sections manually".format(
                        self.__result[parent_hex]['new_key'], new_container_item_proxy_hex))
            else:
                portal_path = portal_result_hex['path']
                new_rg_id_path = '{}+{}'.format(cur_path, portal_path)
                self.__result.update({
                    remote_global_id_hex: {'path': new_rg_id_path,
                                           'new_key': md5_hex(new_rg_id_path),
                                           'type': '{}#{}'.format(self.nodes[container_item_proxy_hex]['isa'],
                                                                  'remoteGlobalIDString')
                                           }
                })

    def __unique_build_phase(self, parent_hex, build_phase_hex):
        """PBXSourcesBuildPhase PBXFrameworksBuildPhase PBXResourcesBuildPhase
        PBXCopyFilesBuildPhase PBXHeadersBuildPhase PBXShellScriptBuildPhase
        """
        self.vprint('uniquify all kinds of PBX*BuildPhase')
        current_node = self.nodes[build_phase_hex]
        # no useful key in some build phase types, use its isa value
        bp_type = current_node['isa']
        if bp_type == 'PBXShellScriptBuildPhase':
            cur_path_key = 'shellScript'
        elif bp_type == 'PBXCopyFilesBuildPhase':
            cur_path_key = ['name', 'dstSubfolderSpec', 'dstPath']
            if not current_node.get('name'):
                del cur_path_key[0]
        else:
            cur_path_key = bp_type
        self.__set_to_result(parent_hex, build_phase_hex, cur_path_key)
        self.vprint('uniquify PBXBuildFile')
        for build_file_hex in current_node['files']:
            self.__unique_build_file(build_phase_hex, build_file_hex)

    def __unique_group_or_ref(self, parent_hex, group_ref_hex):
        """PBXFileReference PBXGroup PBXVariantGroup PBXReferenceProxy"""
        if self.nodes.get(group_ref_hex):
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
            if self.nodes[current_hex]['isa'] == 'PBXReferenceProxy':
                self.__unique_container_item_proxy(parent_hex, self.nodes[current_hex]['remoteRef'])
        else:
            self.vprint("Group/FileReference/ReferenceProxy '", group_ref_hex, "' not found, it will be removed.")
            self.__result.setdefault('to_be_removed', []).append(group_ref_hex)

    def __unique_build_file(self, parent_hex, build_file_hex):
        """PBXBuildFile"""
        current_node = self.nodes.get(build_file_hex)
        if not current_node:
            self.__result.setdefault('to_be_removed', []).append(build_file_hex)
        else:
            file_ref_hex = current_node.get('fileRef')
            if not file_ref_hex:
                self.vprint("PBXFileReference '", file_ref_hex, "' not found, it will be removed.")
                self.__result.setdefault('to_be_removed', []).append(build_file_hex)
            else:
                if self.__result.get(file_ref_hex):
                    cur_path_key = self.__result[file_ref_hex]['path']
                    self.__set_to_result(parent_hex, build_file_hex, cur_path_key)
                else:
                    self.vprint("PBXFileReference '", file_ref_hex, "' not found in PBXBuildFile '", build_file_hex,
                                "'. To be removed.", sep='')
                    self.__result.setdefault('to_be_removed', []).extend((build_file_hex, file_ref_hex))

    def __unique_build_rules(self, parent_hex, build_rule_hex):
        """PBXBuildRule"""
        current_node = self.nodes.get(build_rule_hex)
        if not current_node:
            self.vprint("PBXBuildRule '", current_node, "' not found, it will be removed.")
            self.__result.setdefault('to_be_removed', []).append(build_rule_hex)
        else:
            file_type = current_node['fileType']
            cur_path_key = 'fileType'
            if file_type == 'pattern.proxy':
                cur_path_key = ('fileType', 'filePatterns')
            self.__set_to_result(parent_hex, build_rule_hex, cur_path_key)


class XUniqueExit(SystemExit):
    def __init__(self, value):
        value = "\x1B[31m{}\x1B[0m".format(value)
        super(XUniqueExit, self).__init__(value)


def main():
    usage = "usage: %prog [-v][-u][-s][-c][-p] path/to/Project.xcodeproj"
    description = "Doc: https://github.com/truebit/xUnique"
    parser = OptionParser(usage=usage, description=description)
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="output verbose messages. default is False.")
    parser.add_option("-u", "--unique", action="store_true", dest="unique_bool", default=False,
                      help="uniquify the project file. default is False.")
    parser.add_option("-s", "--sort", action="store_true", dest="sort_bool", default=False,
                      help="sort the project file. default is False. When neither '-u' nor '-s' option exists, xUnique will invisibly add both '-u' and '-s' in arguments")
    parser.add_option("-c", "--combine-commit", action="store_true", dest="combine_commit", default=False,
                      help="When project file was modified, xUnique quit with non-zero status. Without this option, the status code would be zero if so. This option is usually used in Git hook to submit xUnique result combined with your original new commit.")
    parser.add_option("-p", "--sort-pbx-by-filename", action="store_true", dest="sort_pbx_fn_bool", default=False,
                      help="sort PBXFileReference and PBXBuildFile sections in project file, ordered by file name. Without this option, ordered by MD5 digest, the same as Xcode does.")
    (options, args) = parser.parse_args(sys_argv[1:])
    if len(args) < 1:
        parser.print_help()
        raise XUniqueExit(
            "xUnique requires at least one positional argument: relative/absolute path to xcodeproj.")
    xcode_proj_path = decoded_string(args[0])
    xunique = XUnique(xcode_proj_path, options.verbose)
    if not (options.unique_bool or options.sort_bool):
        print_ng("Uniquify and Sort")
        xunique.unique_project()
        xunique.sort_pbxproj(options.sort_pbx_fn_bool)
        success_print("Uniquify and Sort done")
    else:
        if options.unique_bool:
            print_ng('Uniquify...')
            xunique.unique_project()
        if options.sort_bool:
            print_ng('Sort...')
            xunique.sort_pbxproj(options.sort_pbx_fn_bool)
    if options.combine_commit:
        if xunique.is_modified:
            raise XUniqueExit("File 'project.pbxproj' was modified, please add it and then commit.")
    else:
        if xunique.is_modified:
            warning_print(
                "File 'project.pbxproj' was modified, please add it and commit again to submit xUnique result.\nNOTICE: If you want to submit xUnique result combined with original commit, use option '-c' in command.")


if __name__ == '__main__':
    main()
