import testdata
import string

def fn_for_hash(h):
    return 'fastpbkdf2_hmac_' + h

def fmt(xs):
    out = []

    # in C hex escapes are the longest possible sequence of hex
    # digits.  make sure we don't form one longer than two digits!
    lasthex = False

    for x in xs:
        if x.isalpha() and not (lasthex and x in string.hexdigits):
            out.append(x)
            lasthex = False
        else:
            out.append('\\x%02x' % ord(x))
            lasthex = True

    return ''.join(out)

for hash, tests in sorted(testdata.tests.items()):
    print '  printf("%s (%d tests):\\n");' % (hash, len(tests))
    for t in tests:
        print """  check(%s,
        "%s", %d,
        "%s", %d,
        %d,
        "%s", %d);
        """ % (fn_for_hash(hash),
                         fmt(t['password']), len(t['password']),
                         fmt(t['salt']), len(t['salt']),
                         t['iterations'],
                         fmt(t['output']), len(t['output']))
    print '  printf("ok\\n");'
    print
