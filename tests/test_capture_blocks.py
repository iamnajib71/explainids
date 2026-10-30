import pytest

from scripts.capture_blocks import main, session_from_output


def test_session_is_read_from_the_sensor_json_line():
    out = 'Passive capture: keep private.\n{"session": "H:/x/data/sensor/abc123", "rows": 5}\n'
    assert session_from_output(out) == "abc123"


@pytest.mark.parametrize("out", ["", "no json here", "{not json", '{"rows": 3}'])
def test_missing_or_malformed_output_gives_no_session(out):
    assert session_from_output(out) is None


@pytest.mark.parametrize("blocks", ["0", "49"])
def test_block_count_is_bounded(blocks, tmp_path):
    with pytest.raises(SystemExit):
        main(["--interface", "x", "--converter-argv", "[]", "--blocks", blocks, "--study", str(tmp_path / "s.json")])
