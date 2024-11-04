package com.study.springauth.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.study.springauth.entity.User;
import com.study.springauth.security.UserDetailsImpl;

import jakarta.servlet.http.HttpServletRequest;

@Controller
@RequestMapping("/api")
public class ProductController {

	@GetMapping("/products")
	public String getProducts(@AuthenticationPrincipal UserDetailsImpl userDetails) {
		// Authentication 의 Principal 에 저장된 UserDetailsImpl 을 가져옵니다.
		User user =  userDetails.getUser();
		System.out.println("user.getUsername() = " + user.getUsername());

		return "redirect:/";
	}
}


