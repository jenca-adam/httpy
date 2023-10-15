DEFAULT_SETTINGS = {
    "header_table_size": 4096,
    "enable_push": 0,  # disable by default
    "max_concurrent_streams": 128,
    "initial_window_size": 65535,
    "max_frame_size": 16384,
}


class Settings:
    def __init__(self, sd):
        self.settings = getattr(sd, "dict", sd)
        self.__dict__.update(sd)


def merge_settings(server, client):
    sett = dict(DEFAULT_SETTINGS)
    sett.update(server.settings)
    sett.update(client.settings)
    return Settings(sett)
