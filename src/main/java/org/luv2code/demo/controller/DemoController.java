package org.luv2code.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DemoController {

    @GetMapping("/")
    public String showHome() {
        return "home";
    }

    // add a request mapping for /owner
    @GetMapping("/owner")
    public String showOwner() {
        return "owner";
    }

    // add a request mapping for /tester
    @GetMapping("/tester")
    public String showTester() {
        return "tester";
    }

}
