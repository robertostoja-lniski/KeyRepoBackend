import configparser

CONFIG_FILE = "backend.ini"
parser = configparser.ConfigParser()
parser.read(CONFIG_FILE)


def config_data(label, sub_label):
    return parser.get(label, sub_label)
