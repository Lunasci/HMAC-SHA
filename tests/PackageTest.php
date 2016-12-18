<?php

use Lunasci\Package\Package;

class PackageTest extends PHPUnit_Framework_TestCase {

  public function testNachHasCheese()
  {
    $package = new Package;
    $this->assertTrue($package->hasCheese());
  }

}
