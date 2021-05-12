

export { # Record for calculating number stats
	type avg_measure: record {
	    cnt: count &default=0;
	    min: double &default=0.0;
	    max: double &default=0.0;
	    sum: double &default=0.0;
	};
}

# Update stats for a given number value 
function update_val_stats(rec: avg_measure, value: double)
    {
    # increment the sample count
    rec$cnt += 1;

    # add new value to sum
    rec$sum += value;

    # check if new min
    if (value < rec$min)
        {
        rec$min = value;
        }
    # or if new max 
    else if (value > rec$max)
        {
        rec$max = value;
        }
    }