package com.kafkamgt.uiapi.controller;

import com.kafkamgt.uiapi.model.charts.JmxOverview;
import com.kafkamgt.uiapi.model.charts.TeamOverview;
import com.kafkamgt.uiapi.service.MetricsControllerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class MetricsController {

    @Autowired
    MetricsControllerService metricsControllerService;

    @RequestMapping(value = "/getBrokerTopMetrics", method = RequestMethod.GET, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<JmxOverview> getBrokerTopMetrics() {
        return new ResponseEntity<>(metricsControllerService.getBrokerTopMetrics(), HttpStatus.OK);
    }
}
