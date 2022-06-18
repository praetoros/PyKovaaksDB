import configparser
import csv
import math
import os
import re
from datetime import datetime
from tkinter import ttk, messagebox
import keyring
import configuration_files as config_files


def reset_frame(new_frame, master):
    clear_frame(master)
    return default_window_frame(new_frame, master)


def clear_frame(master):
    for widgets in master.winfo_children():
        widgets.destroy()


def default_window_frame(frame, master):
    frame = ttk.Frame(master=master, name=frame)
    frame.grid(sticky='nsew')
    return frame


def forget_frame_contents(master):
    for widgets in master.winfo_children():
        widgets.grid_forget()


def add_toolbar_button(master, text, command, grid_c):
    button = ttk.Button(master=master, text=text, command=command)
    button.grid(row=0, column=grid_c)
    return button


def keyring_get_password(system, username):
    return keyring.get_password(system, username)


def keyring_set_password(system, username, password):
    keyring.set_password(system, username, password)


def config_check_exists(config_file_path):
    return os.path.exists(config_file_path)


def config_alert_create_default():
    messagebox.showinfo(title='No Config File Found',
                        message='No Config File Found.\nCreate new config with default settings?')
    return True


def config_alert_update_invalid(config_invalid):
    config_invalid = len(config_invalid)
    s = ''
    this = 'this'
    if config_invalid > 1:
        s = 's'
        this = 'these'
    response = messagebox.askquestion(title='Config File Invalid Entries',
                                      message=f'Config File has {config_invalid} invalid entries.\n'
                                              f'Yes = Reset only {this} {config_invalid} line{s} to default\n'
                                              f'No = Reset whole config File to default')
    if response == 'yes':
        return True
    else:
        return False


def config_create_default(config_file_path):
    print('Create New Config')
    validation_dict = config_files.validation_dict
    config = configparser.ConfigParser()
    for section in validation_dict.keys():
        config[section] = {}
        for key in validation_dict[section].keys():
            config[section][key] = str(validation_dict[section][key]['default'])
    with open(config_file_path, 'w') as config_file:
        config.write(config_file)


def config_validation_lines(config_file_path):
    # TODO: add config line validator
    config = configparser.ConfigParser()
    config.read(config_file_path)
    validation_errors = []
    validation_dict = config_files.validation_dict
    for section in validation_dict.keys():
        if section not in config:
            validation_errors.append({
                'error': 'section not in config',
                'error-data': section,
                'type': 0,
                'section': section
            })
            continue
        for key in validation_dict[section].keys():
            if key not in config[section]:
                validation_errors.append({
                    'error': 'key not in config[section]',
                    'error-data': f'{section}.{key}',
                    'type': 1,
                    'section': section,
                    'key': key
                })
                continue
            checking_value = config[section][key]
            if config[section][key] == validation_dict[section][key]['default']:
                continue
            length = len(checking_value)
            if length < validation_dict[section][key]['range'][0] or \
                    length > validation_dict[section][key]['range'][1]:
                validation_errors.append({
                    'error': 'length out of range',
                    'error-data': length,
                    'type': 1,
                    'section': section,
                    'key': key
                })
                continue
            if not re.search(validation_dict[section][key]['re'], checking_value):
                validation_errors.append({
                    'error': 're mismatch',
                    'error-data': checking_value,
                    'type': 1,
                    'section': section,
                    'key': key
                })
                continue

    return validation_errors


def config_update_invalid(config_invalid, config_file_path):
    config = config_load(config_file_path)
    validation_dict = config_files.validation_dict
    for invalid_line in config_invalid:
        if invalid_line['type'] == 0:
            config.add_section(invalid_line['section'])
            with open(config_file_path, 'w') as config_file:
                config.write(config_file)
        if invalid_line['type'] == 1:
            config_update(config, config_file_path, invalid_line['section'], invalid_line['key'],
                          validation_dict[invalid_line['section']][invalid_line['key']]['default'])
        print(f'validated {invalid_line}')


def config_update(config, config_file_path, section, key, value):
    str_value = str(value)
    config.set(section, key, str_value)
    with open(config_file_path, 'w') as config_file:
        config.write(config_file)


def config_load(config_file_path):
    print('Load Config')
    config = configparser.ConfigParser()
    config.read(config_file_path)
    return config


def get_csv_data(csv_files, stats_dir):
    output_data = []

    for csvFile in csv_files:
        write_to = ''
        data_kill = []
        data_weapon = []
        data_other = [['fileName', csvFile]]
        with open(os.path.join(stats_dir, csvFile), 'r') as file:
            csvreader = csv.reader(file)
            for row in csvreader:
                if len(row) != 0:
                    match row[0]:
                        case 'Kill #':
                            write_to = 'data_kill'
                            continue
                        case 'Weapon':
                            write_to = 'data_weapon'
                            continue
                        case 'Kills:':
                            write_to = 'data_other'
                    match write_to:
                        case 'data_kill':
                            data_kill.append(row)
                        case 'data_weapon':
                            data_weapon.append(row)
                        case 'data_other':
                            data_other.append(row)
        output_data.append([[csvFile].copy(), data_other.copy(), data_kill.copy(), data_weapon.copy()])
    return output_data


def upload_create_dict(data):
    return_list = []
    for instance in data:
        other_data_dict = other_data_to_dict(instance[1])
        kill_data_list = kill_data_to_list(instance[2])
        weapon_data_list = weapon_data_to_list(instance[3])
        return_list.append({
            'data': other_data_dict,
            'kill': kill_data_list,
            'weapon': weapon_data_list
        })
    return return_list


def other_data_to_dict(data):
    other_data_dict = {}
    required_data_list = {
        "scenario": "None",
        "score": 0,
        "version": "0",
        "sensitivityH": 0,
        "sensitivityV": 0,
        "dpi": 0,
        "sensitivityType": "None",
        "resolution": "None",
        "fpsMax": 0,
        "fpsAvg": 0,
        "hash": "None",
        "datePlayed": "0000-00-00 00:00:0",
        "fileName": "None"
    }
    for data_type in data:
        match data_type[0]:
            case 'Scenario:':
                other_data_dict["scenario"] = data_type[1]
            case 'Score:':
                other_data_dict["score"] = data_type[1]
            case 'Game Version:':
                other_data_dict["version"] = data_type[1]
            case 'Horiz Sens:':
                other_data_dict["sensitivityH"] = data_type[1]
            case 'Vert Sens:':
                other_data_dict["sensitivityV"] = data_type[1]
            case 'DPI:':
                other_data_dict["dpi"] = data_type[1]
            case 'Sens Scale:':
                other_data_dict["sensitivityType"] = data_type[1]
            case 'Resolution:' | 'Resolution':
                other_data_dict["resolution"] = data_type[1]
            case 'Max FPS (config):':
                other_data_dict["fpsMax"] = data_type[1]
            case 'Avg FPS:' | 'Avg FPS':
                other_data_dict["fpsAvg"] = data_type[1]
            case 'Hash:':
                other_data_dict["hash"] = data_type[1]
            case 'fileName':
                other_data_dict["fileName"] = data_type[1]
                string_time = re.search(r'(\d{4}.\d{2}.\d{2}-\d{2}.\d{2}.\d{2})', data_type[1])
                if string_time:
                    other_data_dict["datePlayed"] = datetime.strftime(
                        datetime.strptime(string_time.group(0), '%Y.%m.%d-%H.%M.%S'),
                        '%Y-%m-%d %H:%M:%S')
                else:
                    other_data_dict["datePlayed"] = '0000-00-00 00:00:00'
        for dict_key in required_data_list:
            if dict_key not in other_data_dict.keys():
                other_data_dict[dict_key] = required_data_list[dict_key]
    return other_data_dict


def kill_data_to_list(data, ):
    reformatted = []
    for line in data:
        if line[11] == 'FALSE':
            line[11] = 0
        elif line[11] == 'TRUE':
            line[11] = 1
        time_to_kill = re.search(r"(\d*\.\d*)", line[4])
        if time_to_kill:
            time_to_kill = float(time_to_kill.group())
            time_to_kill = time_to_kill * 1000
            time_to_kill = int(math.floor(time_to_kill))
        else:
            time_to_kill = 0
        reformatted.append(
            {
                "number": line[0],
                "timestamp": line[1],
                "bot": line[2],
                "weapon": line[3],
                "ttk": time_to_kill,
                "shots": line[5],
                "hits": line[6],
                "accuracy": line[7],
                "damageDone": line[8],
                "damagePossible": line[9],
                "efficiency": line[10],
                "cheated": line[11]
            })
    return reformatted


def weapon_data_to_list(data):
    reformatted = []
    line_number = 1
    for line in data:
        if float(line[1]) > 0:
            acc = float(line[2]) / float(line[1])
        else:
            acc = 0
        reformatted.append({
            "number": line_number,
            "accuracy": acc,
            "weapon": line[0],
            "shots": line[1],
            "hits": line[2],
            "damageDone": line[3],
            "damagePotential": line[4]
        })
        line_number += 1

    return reformatted
