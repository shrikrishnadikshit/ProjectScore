from app.collectors import jslibs

PAGE = """
<html><head>
<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
<script src="/static/js/jquery-ui-1.12.1.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js"></script>
<script src='/assets/app.js?v=1.2.3'></script>
</head></html>
"""


def test_detect_versions():
    assert dict(jslibs.detect(PAGE)) == {"jQuery": "3.4.1", "jQuery UI": "1.12.1", "AngularJS": "1.8.2",
                                         "Bootstrap": "5.3.3", "Lodash": "4.17.15"}


def test_evaluate():
    codes = {f.code for f in jslibs.evaluate("a.example", PAGE)}
    assert codes == {"jquery_vulnerable", "jqueryui_vulnerable", "angularjs_eol", "lodash_vulnerable"}
    assert jslibs.evaluate("a.example", '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>') == []
    old = jslibs.evaluate("a.example", '<script src="/js/jquery-1.8.3.js"></script>')
    assert old[0].code == "jquery_vulnerable_old" and old[0].severity == "high"
