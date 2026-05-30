# Grafana Dashboard

This directory contains the optional Grafana dashboard for OpenWRT Netmon Lite.

Grafana and Prometheus should run on the LAN server or another LAN host. Do not run them on the OpenWRT router.

## Prometheus scrape config

Enable the exporter in `config.example.yaml` or via environment variables:

```yaml
metrics:
  prometheus_enabled: true
  prometheus_path: "/metrics"
```

Prometheus scrape example:

```yaml
scrape_configs:
  - job_name: "openwrt-netmon-lite"
    static_configs:
      - targets: ["192.168.10.10:8080"]
```

If `security.dashboard_token` is set, include the token in the scrape path or configure an HTTP header in Prometheus:

```yaml
scrape_configs:
  - job_name: "openwrt-netmon-lite"
    metrics_path: "/metrics"
    params:
      token: ["replace-with-token"]
    static_configs:
      - targets: ["192.168.10.10:8080"]
```

## Import

Import `openwrt-netmon-lite-dashboard.json` in Grafana and choose your Prometheus datasource when prompted.

The top-device panels require:

```yaml
metrics:
  include_device_labels: true
```

Leave device labels disabled for lower-cardinality metrics. The global health, device count, WAN rate, WAN attack, syslog, parser, and buffer panels work without per-device labels.
