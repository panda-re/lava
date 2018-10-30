console.log("Hello world")

var a = 1
var b = 0x100;
var c = "Andrew was here";

if (c[0]+c[1]+c[2] == "HEY") {
    alert("WINNING");
}

// From docs
var val3 = new Date(123456789e3);
var logger = new Duktape.Logger(); 
logger.info('three values:', a, b, val3);

// coroutine.js
function yielder(x) {
    var yield = Duktape.Thread.yield;

    print('yielder starting');
    print('yielder arg:', x);

    print('resumed with', yield(1));
    print('resumed with', yield(2));
    print('resumed with', yield(3));

    print('yielder ending');
    return 123;
}

var t = new Duktape.Thread(yielder);

print('resume test');
print('yielded with', Duktape.Thread.resume(t, 'foo'));
print('yielded with', Duktape.Thread.resume(t, 'bar'));
print('yielded with', Duktape.Thread.resume(t, 'quux'));
print('yielded with', Duktape.Thread.resume(t, 'baz'));
print('finished');

function foo() {
    var myValue = 123;

    function bar() {
        // myValue will be 123, looked up from 'foo' scope

        print(myValue);
    }

    return bar;
}

foo();
