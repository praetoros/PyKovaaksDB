import json
import os
import re
import webbrowser
from os import listdir
from tkinter import *
from tkinter import ttk, filedialog

import numpy as np
import requests
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

import functions
import logging


class App:
    def __init__(self, root):
        self.t_view_data_selected_scenario_data = None
        self.t_view_frame_display_graph = None
        self.session_api_auth = ''
        self.t_view_button_refresh_scenario_selector = None
        self.t_view_combo_scenario_selector = None
        self.t_view_selected_scenario = None
        self.t_view_label_select_scenario = None
        self.t_upload_label_upload_status = None
        self.t_upload_label_count_dict_created = None
        self.t_upload_label_auto = None
        self.t_upload_label_step_by_step = None
        self.t_upload_button_upload_json_via_post = None
        self.t_upload_button_upload_create_dict_from_csv = None
        self.t_upload_label_find_and_upload_status = None
        self.t_upload_button_find_and_upload = None
        self.upload_data_dict = None
        self.files_to_be_uploaded = []
        self.t_upload_button_get_files_to_upload = None
        self.tb_account = None
        self.tb_upload = None
        self.tb_view = None
        self.tb_settings = None
        self.tb_exit = None
        self.dirname = os.path.abspath(os.path.join(os.path.dirname(__file__), '.', ))
        self.dirname_config = os.path.join(self.dirname, 'config.ini')
        self.dirname_log = os.path.join(self.dirname, 'log.log')

        self.keyring_system_name = 'PraetorosKovaaksDbKeyring'
        self.user_public_id = ""
        self.settings_dict = {}
        self.after_autologin_last_tab = None
        self.account_autologin_once = None
        self.build_base_url = None
        self.config = None
        self.keyring_password = None
        self.keyring_username = None
        self.account_remembered_username = StringVar(value='')
        self.account_remembered_password = StringVar(value='')
        self.config_account_auto_login = None
        self.config_account_remember_login = None
        self.t_account_auto_login = None
        self.t_account_logout = None
        self.account_logged_in = False
        self.t_account_password_label = None
        self.t_account_username_label = None
        self.t_account_save_login = None
        self.t_account_password = None
        self.t_account_username = None
        self.t_account_login = None
        self.t_account_register = None
        self.t_upload_csv_files = None
        self.t_upload_folder_path = None
        self.t_upload_label_count_files_to_upload = None
        self.t_upload_label_number_files_found = None
        self.t_upload_button_check_for_csv = None
        self.t_upload_entry_display_selected_folder = None
        self.t_upload_button_browse_folder_location = None
        self.window = None
        self.toolbar = None
        self.mainframe = None

        self.root = root
        self.logger = self.init_logger()
        self.config_window()
        self.init_mainframe()
        self.init_toolbar()
        self.init_config()
        self.init_windows()
        self.display_account()

    def init_logger(self):
        logger = logging.getLogger('log')
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(self.dirname_log)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.info(msg='')
        logger.debug(msg='APPLICATION STARTUP')
        logger.info(msg='init_logger')
        return logger

    def app_exit(self):
        self.logger.info(msg='Called app_exit')
        self.root.quit()

    def init_config(self):
        self.logger.info(msg='Called init_config')
        if not functions.config_check_exists(config_file_path=self.dirname_config):
            functions.config_alert_create_default()
            functions.config_create_default(config_file_path=self.dirname_config)
        config_invalid = functions.config_validation_lines(config_file_path=self.dirname_config)
        self.logger.info(f'{len(config_invalid)} invalid lines')
        if len(config_invalid):
            for config_issue in config_invalid:
                self.logger.warning(msg=json.dumps(config_issue))
            if functions.config_alert_update_invalid(config_invalid):
                functions.config_update_invalid(config_invalid, self.dirname_config)
                key_empty = functions.config_validation_lines(config_file_path=self.dirname_config)
                for key_error in key_empty:
                    self.logger.warning(msg=json.dumps(key_error))
                functions.config_update_invalid(key_empty, config_file_path=self.dirname_config)
            else:
                functions.config_create_default(config_file_path=self.dirname_config)
        self.config = functions.config_load(config_file_path=self.dirname_config)
        self.build_base_url = self.config['build']['base_url']
        self.keyring_username = self.config['keyring']['username']
        self.keyring_password = functions.keyring_get_password(self.keyring_system_name, self.keyring_username)
        self.config_account_remember_login = IntVar(value=int(self.config['account']['remember_login']))
        self.config_account_auto_login = IntVar(value=int(self.config['account']['auto_login']))
        self.t_upload_folder_path = self.config['user']['csv_directory']
        self.after_autologin_last_tab = self.config['user']['last_tab']

    def config_refresh(self):
        self.config = functions.config_load(config_file_path=self.dirname_config)

    def config_window(self):
        self.logger.info(msg='Called config_window')
        self.root.title('KovaaksDB upload')
        self.root.minsize(960, 540)
        self.root.geometry(f'{int(self.root.winfo_screenwidth() / 2)}x{int(self.root.winfo_screenheight() / 2)}')

    def init_mainframe(self):
        self.logger.info(msg='Called init_mainframe')
        self.mainframe = ttk.Frame(master=self.root, name='mainframe', padding="3 3 12 12")
        self.mainframe.grid(column=0, row=0, sticky='nwes')
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

    def init_toolbar(self):
        self.logger.info(msg='Called init_toolbar')
        self.toolbar = ttk.Frame(master=self.mainframe, name='toolbar', padding="3 3 12 12")
        self.toolbar.grid(row=0, sticky='nwes')
        self.tb_account = functions.add_toolbar_button(self.toolbar, 'Account', self.display_account, 0)
        self.tb_upload = functions.add_toolbar_button(self.toolbar, 'Upload', self.display_upload, 1)
        self.tb_view = functions.add_toolbar_button(self.toolbar, 'View', self.display_view, 2)
        self.tb_settings = functions.add_toolbar_button(self.toolbar, 'Settings', self.display_settings, 3)
        self.tb_exit = functions.add_toolbar_button(self.toolbar, 'Exit', self.app_exit, 6)
        self.tb_upload.config(state=DISABLED)
        self.tb_view.config(state=DISABLED)
        self.tb_settings.config(state=DISABLED)

    def init_windows(self):
        self.logger.info(msg='Called init_windows')
        self.window = ttk.Frame(master=self.mainframe, name='window', padding="3 3 12 12")
        self.window.grid(row=1, sticky='nsew')
        self.init_account()
        self.init_upload()
        self.init_view()
        self.init_settings()

    def init_account(self):
        self.logger.info(msg='Called init_account')
        self.t_account_username_label = ttk.Label(master=self.window, text='Email:')
        self.t_account_password_label = ttk.Label(master=self.window, text='Password:')
        self.t_account_username = ttk.Entry(master=self.window, textvariable=self.account_remembered_username)
        self.t_account_password = ttk.Entry(master=self.window, textvariable=self.account_remembered_password,
                                            show="\u2022")
        self.t_account_save_login = ttk.Checkbutton(master=self.window, text='Remember',
                                                    onvalue=1, offvalue=0,
                                                    variable=self.config_account_remember_login,
                                                    command=self.account_auto_login_status)
        self.t_account_auto_login = ttk.Checkbutton(master=self.window, text='Auto Login',
                                                    onvalue=1, offvalue=0,
                                                    variable=self.config_account_auto_login)
        self.t_account_login = ttk.Button(master=self.window, text="Login", command=self.account_login)
        self.t_account_register = ttk.Button(master=self.window, text="Register", command=self.account_register)
        self.t_account_logout = ttk.Button(master=self.window, text="Logout", command=self.account_logout)
        if self.config_account_remember_login.get():
            self.account_remembered_username.set(value=self.keyring_username)
            self.account_remembered_password.set(value=self.keyring_password)
        if self.config_account_auto_login.get():
            self.account_autologin_once = True

    def init_upload(self):
        self.logger.info(msg='Called init_upload')
        self.t_upload_button_browse_folder_location = ttk.Button(master=self.window, text="Browse",
                                                                 command=self.upload_browse_button)
        self.t_upload_entry_display_selected_folder = ttk.Entry(master=self.window)
        self.t_upload_entry_display_selected_folder.insert(0, self.t_upload_folder_path)
        self.t_upload_entry_display_selected_folder.config(state=DISABLED)
        self.t_upload_button_check_for_csv = ttk.Button(master=self.window, text="Check for Files",
                                                        command=self.upload_get_csv_files)
        self.t_upload_label_number_files_found = ttk.Label(master=self.window)
        self.t_upload_label_count_files_to_upload = ttk.Label(master=self.window)
        self.t_upload_label_auto = ttk.Label(master=self.window, text='Auto Upload')
        self.t_upload_label_step_by_step = ttk.Label(master=self.window, text='Step By Step Upload')
        self.t_upload_button_get_files_to_upload = ttk.Button(master=self.window,
                                                              text="Check what files to be uploaded",
                                                              command=self.upload_check_if_files_uploaded)
        self.t_upload_button_upload_create_dict_from_csv = ttk.Button(master=self.window,
                                                                      text="Convert Files To Json",
                                                                      command=self.upload_create_dict_from_csv)
        self.t_upload_button_upload_json_via_post = ttk.Button(master=self.window,
                                                               text="Upload Json",
                                                               command=self.upload_json_via_post)
        self.t_upload_button_find_and_upload = ttk.Button(master=self.window, text="Find & Upload Files",
                                                          command=self.upload_find_and_upload)
        self.t_upload_label_find_and_upload_status = ttk.Label(master=self.window)
        self.t_upload_label_upload_status = ttk.Label(master=self.window)
        self.t_upload_label_count_dict_created = ttk.Label(master=self.window)

    def init_view(self):
        self.logger.info(msg='Called init_view')
        self.t_view_label_select_scenario = ttk.Label(master=self.window, text='Select Scenario')
        self.t_view_selected_scenario = StringVar()
        self.t_view_button_refresh_scenario_selector = ttk.Button(master=self.window, text="Refresh Scenario List",
                                                                  command=self.view_refresh_scenario_selector)
        self.t_view_combo_scenario_selector = ttk.Combobox(master=self.window,
                                                           textvariable=self.t_view_selected_scenario)
        self.t_view_combo_scenario_selector['state'] = 'readonly'
        self.t_view_combo_scenario_selector.bind('<<ComboboxSelected>>', self.view_scenario_selected)
        self.t_view_frame_display_graph = ttk.Frame(master=self.window, name='t_view_frame_display_graph')

    def init_settings(self):
        self.logger.info(msg='Called init_settings')

    def display_account(self):
        self.logger.info(msg='Called display_account')
        functions.config_update(self.config, self.dirname_config, 'user', 'last_tab', 'display_account')
        functions.forget_frame_contents(self.window)
        self.account_auto_login_status()
        if self.account_logged_in:
            self.t_account_logout.grid(row=0, column=0, padx=5, pady=5)
        else:
            self.t_account_username_label.grid(row=0, column=0, padx=5)
            self.t_account_password_label.grid(row=2, column=0, padx=5)
            self.t_account_username.grid(row=1, column=0, padx=5)
            self.t_account_password.grid(row=3, column=0, padx=5)
            self.t_account_save_login.grid(row=2, column=1, sticky=W, padx=5)
            self.t_account_auto_login.grid(row=3, column=1, sticky=W, padx=5)
            self.t_account_login.grid(row=4, column=0, sticky=W, padx=5, pady=5)
            self.t_account_register.grid(row=4, column=1, sticky=W, padx=5, pady=5)
        if self.account_autologin_once:
            self.logger.info(msg=f'Auto logging on tab {self.after_autologin_last_tab}')
            self.account_autologin_once = False
            self.account_login()
            self.display_user_last_tab(self.after_autologin_last_tab)

    def display_upload(self):
        self.logger.info(msg='Called display_upload')
        functions.config_update(self.config, self.dirname_config, 'user', 'last_tab', 'display_upload')
        functions.forget_frame_contents(self.window)
        self.t_upload_button_browse_folder_location.grid(row=0, column=0, padx=5, pady=5)
        self.t_upload_entry_display_selected_folder.grid(row=0, column=1, padx=5, pady=5)

        self.t_upload_label_auto.grid(row=2, column=0, padx=5, pady=5)
        self.t_upload_button_find_and_upload.grid(row=3, column=0, padx=5, pady=5, sticky='we')
        self.t_upload_label_find_and_upload_status.grid(row=2, column=1, padx=5, pady=5)

        self.t_upload_label_step_by_step.grid(row=5, column=0, padx=5, pady=5)
        self.t_upload_button_check_for_csv.grid(row=6, column=0, padx=5, pady=5, sticky='we')
        self.t_upload_label_number_files_found.grid(row=6, column=1, padx=5, pady=5)
        self.t_upload_button_get_files_to_upload.grid(row=7, column=0, padx=5, pady=5, sticky='we')
        self.t_upload_label_count_files_to_upload.grid(row=7, column=1, padx=5, pady=5)
        self.t_upload_button_upload_create_dict_from_csv.grid(row=8, column=0, padx=5, pady=5, sticky='we')
        self.t_upload_label_count_dict_created.grid(row=8, column=1, padx=5, pady=5)
        self.t_upload_button_upload_json_via_post.grid(row=9, column=0, padx=5, pady=5, sticky='we')
        self.t_upload_label_upload_status.grid(row=9, column=1, padx=5, pady=5)

    def display_view(self):
        self.logger.info(msg='Called display_view')
        functions.config_update(self.config, self.dirname_config, 'user', 'last_tab', 'display_view')
        functions.forget_frame_contents(self.window)
        self.view_refresh_scenario_selector()
        self.t_view_label_select_scenario.grid(row=0, column=0, padx=5, pady=5)
        self.t_view_button_refresh_scenario_selector.grid(row=0, column=2, padx=5, pady=5)
        self.t_view_combo_scenario_selector.grid(row=0, column=1, padx=5, pady=5)
        self.t_view_frame_display_graph.grid(row=1, column=3, padx=5, pady=5, sticky='nsew')

    def display_settings(self):
        self.logger.info(msg='Called display_settings')
        functions.config_update(self.config, self.dirname_config, 'user', 'last_tab', 'display_settings')
        functions.forget_frame_contents(self.window)

    def account_auto_login_status(self):
        if self.config_account_remember_login.get():
            self.t_account_auto_login.config(state=NORMAL)
        else:
            self.config_account_auto_login.set(value=0)
            self.window.update()
            self.t_account_auto_login.config(state=DISABLED)

    def account_login(self):
        self.logger.info(msg='account - Sent Login Request')
        self.t_account_login.config(state=DISABLED)
        post_dict = {
            "username": str.lower(self.t_account_username.get()),
            "password": self.t_account_password.get()
        }
        url = self.build_base_url + 'api/auth.php'
        resp = requests.post(url=url, data=post_dict).json()
        if not resp['status']:
            self.account_logged_in = True
            self.user_public_id = resp['data']['user']
            self.session_api_auth = resp['data']['auth']
            self.logger.info(msg='account - login success')
            functions.config_update(self.config, self.dirname_config, 'account', 'remember_login',
                                    self.config_account_remember_login.get())
            functions.config_update(self.config, self.dirname_config, 'account', 'auto_login',
                                    self.config_account_auto_login.get())
            if self.config_account_remember_login.get():
                self.logger.info(msg='account - login saved')
                functions.config_update(self.config, self.dirname_config, 'keyring', 'username',
                                        self.t_account_username.get())
                functions.keyring_set_password(self.keyring_system_name,
                                               self.keyring_username,
                                               self.t_account_password.get())
            self.account_logged_in = True
            self.tb_upload.config(state=NORMAL)
            self.tb_view.config(state=NORMAL)
            self.tb_settings.config(state=NORMAL)
            self.display_account()
        else:
            self.t_account_login.config(state=NORMAL)
            print('login failed')

    def display_user_last_tab(self, last_tab):
        if last_tab == 'display_account':
            self.display_account()
        elif last_tab == 'display_upload':
            self.display_upload()
        elif last_tab == 'display_view':
            self.display_view()
        elif last_tab == 'display_settings':
            self.display_settings()

    def account_register(self):
        webbrowser.open(f'{self.build_base_url}register.php', new=2)

    def account_logout(self):
        self.logger.info(msg='account - logged out')
        self.t_account_login.config(state=NORMAL)
        self.tb_upload.config(state=DISABLED)
        self.tb_view.config(state=DISABLED)
        self.tb_settings.config(state=DISABLED)
        self.account_logged_in = False
        self.display_account()

    def upload_browse_button(self):
        filename = filedialog.askdirectory()
        functions.config_update(self.config, self.dirname_config, 'user', 'csv_directory', filename)
        self.t_upload_folder_path = filename
        self.t_upload_entry_display_selected_folder.config(state=NORMAL)
        self.t_upload_entry_display_selected_folder.delete(0, END)
        self.t_upload_entry_display_selected_folder.insert(0, filename)
        self.t_upload_entry_display_selected_folder.config(state=DISABLED)
        self.upload_get_csv_files()

    def upload_get_csv_files(self):
        if isinstance(self.t_upload_folder_path, str) and len(self.t_upload_folder_path) > 0:
            self.t_upload_csv_files = []
            for dirFile in listdir(self.t_upload_folder_path):
                if re.search(r"\d{4}.\d{2}.\d{2}-\d{2}.\d{2}.\d{2} Stats.csv$", dirFile):
                    self.t_upload_csv_files.append(dirFile)
            self.t_upload_label_number_files_found['text'] = f"{len(self.t_upload_csv_files)} csv Files Found"

    def upload_check_if_files_uploaded(self):
        self.logger.info(msg=f'Checking Status of {len(self.t_upload_csv_files)}')
        self.t_upload_label_count_files_to_upload['text'] = f'Checking Files...'
        file_counter = 0
        check_if_files_uploaded = {}
        for file in self.t_upload_csv_files:
            file_counter += 1
            check_if_files_uploaded[str(file_counter)] = file
        post_dict = {
            "mode": "file",
            "user": self.user_public_id,
            "filenames": check_if_files_uploaded
        }
        url = self.build_base_url + 'apps/upload/upload.php'
        headers = {'Content-Type': 'application/json'}
        resp = requests.post(url=url, headers=headers, json=post_dict)
        data = resp.json()['data']
        self.logger.info(msg=f'{len(data)} of {len(self.t_upload_csv_files)} To be uploaded')
        self.files_to_be_uploaded = []
        for file_reference in data:
            self.files_to_be_uploaded.append(check_if_files_uploaded[str(file_reference)])
        self.files_to_be_uploaded = self.files_to_be_uploaded[0:100]
        self.t_upload_label_count_files_to_upload['text'] = f'{len(self.files_to_be_uploaded)} Files to be uploaded'

    def upload_create_dict_from_csv(self):
        self.logger.info(msg=f'Called upload_create_dict_from_csv on {len(self.files_to_be_uploaded)} files')
        self.t_upload_label_count_dict_created['text'] = f'Creating JSON for {len(self.files_to_be_uploaded)} files...'
        data = functions.get_csv_data(self.files_to_be_uploaded, self.t_upload_folder_path)
        self.upload_data_dict = {}
        self.upload_data_dict = functions.upload_create_dict(data)
        self.t_upload_label_count_dict_created['text'] = f'Created JSON for {len(self.files_to_be_uploaded)} files'

    def upload_json_via_post(self):
        total_attempted = len(self.upload_data_dict)
        self.logger.info(msg=f'Attempting to upload {total_attempted} files')
        self.t_upload_label_upload_status['text'] = f'Uploading....'
        post_dict = {
            "mode": "upload",
            "user": self.user_public_id,
            "data": self.upload_data_dict
        }
        url = self.build_base_url + 'apps/upload/upload.php'
        headers = {'Content-Type': 'application/json'}
        resp = requests.post(url=url, headers=headers, json=post_dict)
        data = resp.json()['data']
        self.logger.info(msg=f'Successfully uploaded {data}'
                             f' of {total_attempted}'
                             f' files, leaving {total_attempted - data} with errors')
        self.t_upload_label_upload_status['text'] = f'Uploaded {data} files'

    def upload_find_and_upload(self):
        self.upload_get_csv_files()
        self.upload_check_if_files_uploaded()
        while self.files_to_be_uploaded:
            self.upload_check_if_files_uploaded()
            self.root.update()
            self.upload_create_dict_from_csv()
            self.root.update()
            self.upload_json_via_post()
            self.root.update()

    def view_refresh_scenario_selector(self):
        get_dict = {
            "user": self.user_public_id
        }
        params = dict(
            auth=self.session_api_auth
        )
        url = self.build_base_url + 'api/get/scenarioByUser.php'
        headers = {'Content-Type': 'application/json'}
        resp = requests.get(url=url, headers=headers, params=params, json=get_dict)
        data = resp.json()['data']
        scenario_selector_list = []
        if not resp.json()['status']:
            for scenario in data:
                scenario_selector_list.append(scenario['scenario'])
            self.t_view_combo_scenario_selector['values'] = scenario_selector_list

    def view_scenario_selected(self, event):
        get_dict = {
            "user": self.user_public_id,
            "scenario": self.t_view_selected_scenario.get()
        }
        params = dict(
            auth=self.session_api_auth
        )
        url = self.build_base_url + 'api/get/dataByUserScenario.php'
        headers = {'Content-Type': 'application/json'}
        resp = requests.get(url=url, headers=headers, params=params, json=get_dict)
        self.t_view_data_selected_scenario_data = resp.json()['data']
        self.view_display_graph_scatter_linear()

    def view_display_graph_scatter_linear(self):
        functions.clear_frame(self.t_view_frame_display_graph)
        score = []
        date = []
        run_num = []
        counter = 1
        for datapoint in self.t_view_data_selected_scenario_data:
            score.append(float(datapoint['score']))
            # date.append(datapoint['date'])
            run_num.append(counter)
            counter += 1
        x = np.array(run_num)
        y = np.array(score)
        a, b = np.polyfit(x, y, 1)
        if len(run_num) == 1:
            window = 1
        elif len(run_num) < 10:
            window = 2
        else:
            window = len(run_num) // 10 + 1
        average_y = []
        for ind in range(len(y) - window + 1):
            average_y.append(np.mean(y[ind:ind + window]))
        for ind in range(window - 1):
            average_y.insert(0, np.nan)
        figure = Figure(figsize=(8, 6), dpi=100)
        figure_canvas = FigureCanvasTkAgg(figure, self.t_view_frame_display_graph)
        # NavigationToolbar2Tk(figure_canvas, self.t_view_frame_display_graph)
        axes = figure.add_subplot()
        axes.scatter(x, y, label='Original data')
        axes.plot(x, a * x + b, 'y', label=f'Linear Line Of Best Fit (Window = {window})')
        axes.plot(x, average_y, 'r-', label='Running average')
        axes.set_title(f'{self.t_view_selected_scenario.get()} Scores')
        axes.set_ylabel('Score')
        axes.legend()
        figure_canvas.get_tk_widget().pack(side=TOP, fill=BOTH, expand=1)
