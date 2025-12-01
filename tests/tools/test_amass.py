import src.tools.amass

def test_amass_module_import():
    """Test that the amass module can be imported and has a __version__."""
    assert hasattr(src.tools.amass, '__version__')
    assert isinstance(src.tools.amass.__version__, str)
