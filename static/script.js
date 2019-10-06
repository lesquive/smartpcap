window.addEventListener("DOMContentLoaded", function(e) {
    var myHilitor2 = new Hilitor("container-fluid");
    myHilitor2.setMatchType("left");
    document.getElementById("searchbar").addEventListener("keyup", function(e) {
      myHilitor2.apply(this.value);
    }, false);
  }, false);

document.addEventListener('DOMContentLoaded', () => {
    const btnHide = document.getElementById('submitbutton');
    btnHide.hidden = true;

    document.getElementById("submitbutton").onclick = function() {myFunction()};

    function myFunction() {
        document.getElementById("container-fluid").innerHTML = '<div class="body"><span><span></span><span></span><span></span><span></span></span><div class="base"><span></span><div class="face"></div></div></div><div class="longfazers"><span></span><span></span><span></span><span></span></div><h1>Analyzing Packet Capture...</h1>';
    }

});


