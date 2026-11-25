import pytest

from router_usage import parse_totals, read_totals


def test_router_totals_exclude_unattributed_rows_and_rank_by_volume():
    actual = parse_totals(
        "mac,conns,rx_bytes,rx_pkts,tx_bytes,tx_pkts\n"
        "00:00:00:00:00:00,1,8000,1,9,1\n"
        "AA:BB:CC:11:22:33,2,400,1,600,1\n"
        "aa:bb:cc:11:22:44,3,1600,1,900,1\n"
    )
    assert actual == [
        {"mac": "aa:bb:cc:11:22:44", "download_bytes": 1600, "upload_bytes": 900},
        {"mac": "aa:bb:cc:11:22:33", "download_bytes": 400, "upload_bytes": 600},
    ]


def test_router_totals_require_valid_counters_and_host_alias():
    with pytest.raises(ValueError):
        parse_totals("mac,rx_bytes,tx_bytes\naa:bb:cc:11:22:33,unknown,600\n")
    with pytest.raises(ValueError):
        read_totals("-oProxyCommand=invalid")
