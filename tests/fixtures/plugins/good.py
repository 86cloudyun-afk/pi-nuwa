PLUGIN = {
    "name": "fake-engine",
    "api_version": "1",
    "run": lambda prompt, opts: "ok:" + prompt[:10],
}
