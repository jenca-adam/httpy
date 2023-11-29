DEFAULT_SETTINGS = {
    "header_table_size": 4096,
    "enable_push": 0,  # disable by default
    "max_concurrent_streams": 128,
    "initial_window_size": 1048560,
    "max_frame_size": 524280,
}


class Settings:
    def __init__(self, sd, client, server):
        self.client_settings = client
        self.server_settings = server
        self.settings = getattr(sd, "dict", sd)
        self.__dict__.update(sd)

    def __getitem__(self, s):
        if self.settings[s] is None and s in DEFAULT_SETTINGS:
            return DEFAULT_SETTINGS[s]
        return self.settings[s]

    def __iter__(self):
        return iter(self.settings)


def merge_settings(server, client):
    sett = dict(DEFAULT_SETTINGS)
    server_settings = getattr(server, "settings", server)
    client_settings = getattr(client, "settings", client)
    sett.update(server_settings)
    sett.update(client_settings)
    return Settings(
        sett, Settings(client_settings, {}, {}), Settings(server_settings, {}, {})
    )


def merge_client_settings(new, old):
    sett = dict(DEFAULT_SETTINGS)
    old.client_settings.update(new)
    old.settings.update(new)
    sett.update(old.settings)
    return Settings(
        sett,
        Settings(old.client_settings, {}, {}),
        Settings(old.server_settings, {}, {}),
    )
